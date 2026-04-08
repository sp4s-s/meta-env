from __future__ import annotations
from typing import Any, Dict, List, Tuple
from .base import TaskHandler
from env.models import Action, EngineState

def _priority(cve: Any) -> float:
    """Ground truth priority score."""
    s_mod = 1.5 if cve.severity == "CRITICAL" else 1.0
    k_mod = 2.0 if getattr(cve, "kev_listed", False) else 1.0
    v_mod = 0.1 if getattr(cve, "vex_status", "a") == "not_affected" else 1.0
    ssvc = {"act": 1.6, "attend": 1.25, "track*": 1.0, "track": 0.75}.get(getattr(cve, "ssvc_decision", "track"), 1.0)
    eps = max(cve.epss_score, getattr(cve, "epss_percentile", 0.05), 0.05)
    return (s_mod * k_mod * v_mod * ssvc * cve.cvss_score * eps) / max(1.0, float(cve.reachability_depth))

def _kt_sim(l1: List[str], l2: List[str]) -> float:
    """Normalized Kendall-Tau distance."""
    if not l1 or not l2: return 0.0
    intersect = [x for x in l1 if x in l2]
    if len(intersect) <= 1: return 1.0 if len(intersect) == 1 else 0.0
    n = len(intersect)
    m2 = {v: i for i, v in enumerate(l2)}
    c, d = 0, 0
    for i in range(n-1):
        for j in range(i+1, n):
            if m2[intersect[i]] < m2[intersect[j]]: c += 1
            else: d += 1
    t = (c - d) / (n * (n - 1) / 2)
    return (t + 1) / 2

class Task1Handler(TaskHandler):
    def execute(self, state: EngineState, action: Action) -> Tuple[float, Dict[str, Any]]:
        if action.action_type == "done":
            state.done = True
            return state.best_task_score, {"score": state.best_task_score}
        
        if action.action_type != "rank" or not action.cve_rankings:
            state.last_action_error = "Invalid rank action"
            return 0.0, {}

        truth = [c.cve_id for c in sorted(state.active_cves, key=_priority, reverse=True)]
        score = _kt_sim(action.cve_rankings, truth)
        state.best_task_score = max(state.best_task_score, score)
        return state.best_task_score, {"curr": score, "best": state.best_task_score}
