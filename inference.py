"""
Baseline inference script for dep-vuln-env.

Runs all 3 tasks against the code-centric RL environment.
Uses LLM when HF_TOKEN is set; falls back to deterministic heuristic.
"""
import json
import os
import re
import sys
from typing import List, Optional

from openai import OpenAI

from env.environment import DepVulnEnv
from env.models import Action, Observation, VulnFinding, RemediationAction
from env.verification import task_completion_score

HF_TOKEN = os.getenv("HF_TOKEN")
API_BASE_URL = os.getenv("API_BASE_URL", "https://litellm.sclr.ac/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")
BENCHMARK = "dep-vuln-env"
TASK_NAMES = {1: "code_vuln_identify", 2: "code_vuln_remediate", 3: "constrained_remediation"}


def log_s(task_name: str) -> None:
    print(f"[START] task={task_name} env={BENCHMARK} model={MODEL_NAME}", flush=True)


def log_st(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} done={str(done).lower()} error={error or 'null'}",
        flush=True,
    )


def log_e(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    serialized = ",".join(f"{reward:.2f}" for reward in rewards)
    print(f"[END] success={str(success).lower()} steps={steps} score={score:.2f} rewards={serialized}", flush=True)


# ── Known vulnerability patterns for heuristic ──────────────────────
_VULN_PATTERNS = {
    "jinja2": ("CVE-2024-56326", "CRITICAL", "3.1.5"),
    "PIL": ("CVE-2024-28219", "CRITICAL", "10.3.0"),
    "pillow": ("CVE-2024-28219", "CRITICAL", "10.3.0"),
    "requests": ("CVE-2024-35195", "MEDIUM", "2.32.0"),
    "tornado": ("CVE-2024-32651", "CRITICAL", "6.4.1"),
    "flask": ("CVE-2023-30861", "HIGH", "3.0.1"),
    "yaml": ("CVE-2024-20060", "HIGH", "6.0.2"),
    "pyyaml": ("CVE-2024-20060", "HIGH", "6.0.2"),
    "django": ("CVE-2024-27351", "HIGH", "5.0.3"),
    "gunicorn": ("CVE-2024-1135", "HIGH", "22.0.0"),
    "transformers": ("CVE-2024-3568", "CRITICAL", "4.38.2"),
    "cryptography": ("CVE-2024-26130", "HIGH", "42.0.4"),
    "express": ("CVE-2024-29041", "MEDIUM", "4.19.2"),
    "body-parser": ("CVE-2024-45590", "HIGH", "1.20.3"),
    "bodyParser": ("CVE-2024-45590", "HIGH", "1.20.3"),
    "axios": ("CVE-2024-39338", "HIGH", "1.7.4"),
    "ws": ("CVE-2024-37890", "HIGH", "8.17.1"),
    "WebSocket": ("CVE-2024-37890", "HIGH", "8.17.1"),
    "elliptic": ("CVE-2024-48949", "CRITICAL", "6.5.6"),
    "ip": ("CVE-2024-29415", "CRITICAL", "2.0.1"),
    "cookie": ("CVE-2024-47764", "MEDIUM", "0.7.0"),
    "cross-spawn": ("CVE-2024-21538", "HIGH", "7.0.5"),
    "json5": ("CVE-2022-46175", "HIGH", "2.2.3"),
}


def _extract_imports(code: str, language: str) -> List[str]:
    """Extract imported module names from code."""
    modules = []
    if language == "python":
        for m in re.finditer(r'(?:from|import)\s+([A-Za-z_][A-Za-z0-9_.]*)', code):
            modules.append(m.group(1).split(".")[0])
    else:
        for m in re.finditer(r'require\(["\']([^"\']+)["\']\)', code):
            modules.append(m.group(1))
    return list(set(modules))


def heuristic(tid: int, obs: Observation, step: int) -> Action:
    """Deterministic heuristic baseline: scan imports for known vulns."""
    # Step 1: identify
    if step == 1 or (tid >= 2 and step <= 2):
        findings = []
        for cf in obs.code_files:
            imports = _extract_imports(cf.content, cf.language)
            for imp in imports:
                if imp in _VULN_PATTERNS:
                    cve, sev, _ = _VULN_PATTERNS[imp]
                    # Find the import line
                    line = 1
                    for i, ln in enumerate(cf.content.split("\n"), 1):
                        if imp in ln:
                            line = i
                            break
                    findings.append(VulnFinding(
                        cve_id=cve, file_path=cf.path, line_number=line,
                        package=imp, severity=sev, explanation=f"Known vuln in {imp}",
                    ))
        if findings:
            return Action(action_type="identify", findings=findings)

    # Step 2+: remediate (tasks 2-3)
    if tid >= 2 and obs.known_vulns:
        # Skip already-remediated CVEs
        already = {h.get("cve") for h in obs.action_history
                   if h.get("type") == "remediate"} if obs.action_history else set()
        for cve in obs.known_vulns:
            if cve in already:
                continue
            for pkg, (cid, sev, fix_ver) in _VULN_PATTERNS.items():
                if cid == cve:
                    return Action(
                        action_type="remediate",
                        remediation=RemediationAction(
                            cve_id=cve,
                            file_path=obs.code_files[0].path if obs.code_files else "unknown",
                            action="upgrade",
                            target_version=fix_ver,
                            justification=f"Upgrade {pkg} to {fix_ver} to fix {cve}",
                        ),
                    )

    return Action(action_type="done")


def get_action(client: OpenAI, tid: int, obs: Observation) -> Action:
    """LLM-driven action selection."""
    code_context = "\n\n".join(
        f"--- {cf.path} ({cf.language}) ---\n{cf.content}" for cf in obs.code_files
    )
    prompt = json.dumps({
        "task": TASK_NAMES[tid],
        "step": obs.step,
        "max_steps": obs.max_steps,
        "code_files": code_context,
        "known_vulns": obs.known_vulns,
        "budget": obs.budget_points,
        "sla_clock": obs.sla_clock,
        "instruction": (
            "Analyze the code for dependency vulnerabilities. "
            "Return JSON with: action_type ('identify'|'remediate'|'rank'|'done'), "
            "findings (list of {cve_id, file_path, line_number, package, severity, explanation}), "
            "remediation ({cve_id, file_path, action, target_version, justification}), "
            "risk_ranking (list of cve_ids)."
        ),
    })
    resp = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": "You are a code security analysis agent. Analyze source code for vulnerable dependencies. Return only JSON."},
            {"role": "user", "content": prompt},
        ],
        response_format={"type": "json_object"},
    )
    raw = json.loads(resp.choices[0].message.content or "{}")

    # Parse findings if present
    findings = None
    if raw.get("findings"):
        findings = [VulnFinding(**f) for f in raw["findings"]]
    rem = None
    if raw.get("remediation"):
        rem = RemediationAction(**raw["remediation"])

    return Action(
        action_type=raw.get("action_type", "done"),
        findings=findings,
        remediation=rem,
        risk_ranking=raw.get("risk_ranking"),
        justification=raw.get("justification"),
    )


def score(tid: int, env: DepVulnEnv, errs: int) -> float:
    del errs
    return task_completion_score(env.state, tid)


def run(client: OpenAI, env: DepVulnEnv, tid: int) -> None:
    log_s(TASK_NAMES[tid])
    obs = env.reset(task_id=tid)
    rs: List[float] = []
    errs = 0
    stp = 0
    try:
        for i in range(1, obs.max_steps + 1):
            e = None
            try:
                a = get_action(client, tid, obs) if HF_TOKEN else heuristic(tid, obs, i)
            except Exception as ex:
                e = str(ex).replace('"', "'")
                a = heuristic(tid, obs, i)
            obs = env.step(a)
            r = float(obs.reward or 0.0)
            last_err = obs.info.get("err")
            if last_err:
                errs += 1
                e = e or str(last_err).replace('"', "'")
            rs.append(r)
            stp = i
            log_st(i, a.model_dump_json(exclude_none=True, exclude_defaults=True), r, obs.done, e)
            if obs.done:
                break
        sc = max(0.02, min(0.98, score(tid, env, errs)))
        log_e(sc >= 0.1, stp, sc, rs)
    except Exception:
        log_e(False, stp, 0.02, rs or [0.0])


def main() -> None:
    client = OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN or "missing-token")
    env = DepVulnEnv()
    for tid in (1, 2, 3):
        run(client, env, tid)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.exit(1)
