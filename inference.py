import json
import os
import sys
from typing import List, Optional

from openai import OpenAI

from env.environment import DepVulnEnv
from env.models import Action, CVEInfo, Observation
from graders.core import grade_task_2, grade_task_3

HF_TOKEN = os.getenv("HF_TOKEN")
API_BASE_URL = os.getenv("API_BASE_URL", "https://litellm.sclr.ac/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")
LOCAL_IMAGE_NAME = os.getenv("LOCAL_IMAGE_NAME")
BENCHMARK = "dep-vuln-env"
TASK_NAMES = {
    1: "cve_triage",
    2: "fix_recommendation",
    3: "constrained_remediation",
}


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


def _risk(cve: CVEInfo) -> float:
    b = 1.5 if cve.severity == "CRITICAL" else 1.0
    if cve.kev_listed: b *= 2.0
    if cve.vex_status == "not_affected": b *= 0.1
    ssvc = {"act": 1.6, "attend": 1.25, "track*": 1.0, "track": 0.75}.get(cve.ssvc_decision, 1.0)
    eps = max(cve.epss_score, cve.epss_percentile, 0.05)
    return (b * ssvc * cve.cvss_score * eps) / max(1.0, float(cve.reachability_depth))


def heuristic(tid: int, obs: Observation, step: int) -> Action:
    active = sorted(obs.active_cves, key=_risk, reverse=True)
    if tid == 1:
        if step >= obs.max_steps:
            return Action(action_type="done")
        return Action(action_type="rank", cve_rankings=[c.cve_id for c in active])
    if not active:
        return Action(action_type="done")

    t = active[0]
    can_fix = obs.budget_points >= 2 and t.fixed_version
    if can_fix and t.severity in ("CRITICAL", "HIGH"):
        return Action(action_type="fix", cve_id=t.cve_id, target_node=t.target_node, target_version=t.fixed_version)
    if t.severity in ("LOW", "NONE") or t.reachability_depth >= 2:
        return Action(action_type="suppress", cve_id=t.cve_id, justification="Transitive/Low impact")
    if t.severity in ("MEDIUM", "LOW", "NONE"):
        return Action(action_type="accept", cve_id=t.cve_id, justification="Risk accepted")
    if can_fix:
        return Action(
            action_type="fix",
            cve_id=t.cve_id,
            target_node=t.target_node,
            target_version=t.fixed_version,
        )
    return Action(action_type="accept", cve_id=t.cve_id, justification="Budget reserved for higher-risk items")


def get_action(client: OpenAI, tid: int, obs: Observation) -> Action:
    prompt = json.dumps(
        {
            "task": TASK_NAMES[tid],
            "observation": json.loads(obs.model_dump_json()),
            "instruction": (
                "Return exactly one JSON object with keys action_type, cve_rankings, cve_id, "
                "target_node, target_version, justification."
            ),
        }
    )
    resp = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": "You are a dependency vulnerability remediation agent. Return only JSON."},
            {"role": "user", "content": prompt},
        ],
        response_format={"type": "json_object"},
    )
    return Action(**json.loads(resp.choices[0].message.content or "{}"))


def score(tid: int, env: DepVulnEnv, errs: int) -> float:
    s = env.state
    if tid == 1:
        return env.normalized_score()
    if tid == 2:
        return grade_task_2(s.initial_cve_count, len(s.resolved_cves), errs)
    cr = sum(1 for c in s.active_cves if c.severity == "CRITICAL")
    hr = sum(1 for c in s.active_cves if c.severity == "HIGH")
    return grade_task_3(s.initial_cve_count, len(s.resolved_cves), cr, hr, s.budget_points, s.sla_clock)


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
            last_error = obs.info.get("error") or obs.info.get("last_action_error")
            if last_error:
                errs += 1
                e = e or str(last_error).replace('"', "'")
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
