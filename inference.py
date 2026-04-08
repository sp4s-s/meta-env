import json
import os
import sys
from typing import List, Optional
from openai import OpenAI
from env.environment import DepVulnEnv
from env.models import Action, CVEInfo, Observation
from graders.core import grade_task_2, grade_task_3

# Env config
KEY = os.getenv("API_KEY") or os.getenv("HF_TOKEN") or os.getenv("OPENAI_API_KEY", "")
URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MDL = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")

def log_s(t: str): print(f"[START] task={t} env=dep-vuln-env model={MDL}", flush=True)
def log_st(s: int, a: str, r: float, d: bool, e: str | None):
    print(f"[STEP] step={s} action={a} reward={r:.2f} done={str(d).lower()} error={e or 'null'}", flush=True)
def log_e(scc: bool, stp: int, sc: float, rs: List[float]):
    print(f"[END] success={str(scc).lower()} steps={stp} score={sc:.3f} rewards={','.join(f'{r:.2f}' for r in rs)}", flush=True)

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
        return Action(action_type="done") if step >= obs.max_steps else Action(action_type="rank", cve_rankings=[c.cve_id for c in active])
    if not active: return Action(action_type="done")
    
    t = active[0]
    can_fix = obs.budget_points >= 2 and t.fixed_version
    if can_fix and t.severity in ("CRITICAL", "HIGH"):
        return Action(action_type="fix", cve_id=t.cve_id, target_node=t.target_node, target_version=t.fixed_version)
    if t.severity in ("LOW", "NONE") or t.reachability_depth >= 2:
        return Action(action_type="suppress", cve_id=t.cve_id, justification="Transitive/Low impact")
    if t.severity in ("MEDIUM", "LOW", "NONE"):
        return Action(action_type="accept", cve_id=t.cve_id, justification="Risk accepted")
    return Action(action_type="fix" if can_fix else "accept", cve_id=t.cve_id, target_node=t.target_node, target_version=t.fixed_version)

def get_action(c: OpenAI, tid: int, obs: Observation) -> Action:
    resp = c.chat.completions.create(
        model=MDL,
        messages=[{"role": "system", "content": "Return remediation JSON."}, {"role": "user", "content": obs.model_dump_json()}],
        response_format={"type": "json_object"}
    )
    return Action(**json.loads(resp.choices[0].message.content))

def score(tid: int, env: DepVulnEnv, errs: int) -> float:
    s = env.state
    if tid == 1: return env.normalized_score()
    if tid == 2: return grade_task_2(s.initial_cve_count, len(s.resolved_cves), errs)
    cr = sum(1 for c in s.active_cves if c.severity == "CRITICAL")
    hr = sum(1 for c in s.active_cves if c.severity == "HIGH")
    return grade_task_3(s.initial_cve_count, len(s.resolved_cves), cr, hr, s.budget_points, s.sla_clock)

def run(c: OpenAI, env: DepVulnEnv, tid: int):
    log_s({1:"cve_triage", 2:"fix_recommendation", 3:"constrained_remediation"}[tid])
    obs = env.reset(tid)
    rs, errs, stp = [], 0, 0
    try:
        for i in range(1, obs.max_steps + 1):
            e = None
            try:
                a = get_action(c, tid, obs) if KEY else heuristic(tid, obs, i)
            except Exception as ex:
                e, a = str(ex), heuristic(tid, obs, i)
            obs = env.step(a)
            r = float(obs.reward or 0.0)
            if obs.info.get("err"): errs += 1; e = e or obs.info["err"]
            rs.append(r)
            stp = i
            log_st(i, a.model_dump_json(exclude_none=True), r, obs.done, e)
            if obs.done: break
        sc = max(0.02, min(0.98, score(tid, env, errs)))
        log_e(sc >= 0.1, stp, sc, rs)
    except Exception as ex:
        log_e(False, stp, 0.02, rs or [0.0])

def main():
    c = OpenAI(base_url=URL, api_key=KEY or "none")
    env = DepVulnEnv()
    for tid in (1, 2, 3): run(c, env, tid)

if __name__ == "__main__":
    try: main()
    except Exception: sys.exit(1)
