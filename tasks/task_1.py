"""
Task 1: Code Vulnerability Identification (Easy)

Agent receives code blocks and must identify which CVEs are present
by analyzing imports, usage patterns, and vulnerable API calls.
Scored by precision/recall of identified CVEs + line-level accuracy.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from .base import TaskHandler, apply_identification
from env.models import Action, EngineState
from env.verification import task_completion_score, weighted_ranking_score


def _kt_sim(l1: List[str], l2: List[str]) -> float:
    """Normalized Kendall-Tau similarity for ranking comparison."""
    if not l1 or not l2:
        return 0.0
    intersect = [x for x in l1 if x in l2]
    if len(intersect) <= 1:
        return 1.0 if len(intersect) == 1 else 0.0
    n = len(intersect)
    m2 = {v: i for i, v in enumerate(l2)}
    c, d = 0, 0
    for i in range(n - 1):
        for j in range(i + 1, n):
            if m2[intersect[i]] < m2[intersect[j]]:
                c += 1
            else:
                d += 1
    t = (c - d) / (n * (n - 1) / 2)
    return (t + 1) / 2


def _priority(cve_id: str, state: EngineState) -> float:
    evidence = state.ground_truth_evidence.get(cve_id)
    if evidence is None:
        return 1.0
    sev_w = {"CRITICAL": 1.5, "HIGH": 1.2, "MEDIUM": 1.0, "LOW": 0.6, "NONE": 0.3}
    return evidence.cvss_score * sev_w.get(evidence.severity, 1.0)


class Task1Handler(TaskHandler):
    """
    Identification task: agent must find vulnerabilities in code.

    Actions:
    - identify: submit VulnFinding list
    - rank: submit risk ranking of found CVEs
    - done: end episode

    Scoring: F1 of identified CVEs, bonus for line accuracy.
    """

    def execute(self, state: EngineState, action: Action) -> Tuple[float, Dict[str, Any]]:
        if action.action_type == "done":
            state.done = True
            state.best_task_score = max(state.best_task_score, task_completion_score(state, state.task_id))
            return state.best_task_score, {"score": round(state.best_task_score, 4)}

        if action.action_type == "identify":
            return self._handle_identify(state, action)

        if action.action_type == "rank":
            return self._handle_rank(state, action)

        state.last_action_error = f"Task1 does not support: {action.action_type}"
        return 0.0, {}

    def _handle_identify(self, state: EngineState, action: Action) -> Tuple[float, Dict[str, Any]]:
        if not action.findings:
            state.last_action_error = "No findings submitted"
            return 0.0, {}

        info = apply_identification(state, action.findings)
        precision = len(state.identified_vulns) / max(1, len(state.identified_vulns) + len(state.false_positives))
        recall = len(state.identified_vulns) / max(1, len(state.ground_truth_vulns))
        score = task_completion_score(state, state.task_id)
        state.best_task_score = max(state.best_task_score, score)

        return score, {
            "tp": info["accepted"],
            "partial": info["partial"],
            "fp": info["fp"],
            "recall": round(recall, 3),
            "precision": round(precision, 3),
            "line_hits": info["line_hits"],
            "evidence_gain": info["evidence_gain"],
            "score": round(score, 3),
        }

    def _handle_rank(self, state: EngineState, action: Action) -> Tuple[float, Dict[str, Any]]:
        if not action.risk_ranking:
            state.last_action_error = "No ranking submitted"
            return 0.0, {}

        truth_order = sorted(state.ground_truth_vulns,
                             key=lambda c: _priority(c, state), reverse=True)
        score = weighted_ranking_score(action.risk_ranking, state.ground_truth_evidence)
        state.best_task_score = max(state.best_task_score, score)
        state.risk_ranking_score = max(state.risk_ranking_score, score)
        return score, {"ranking_sim": round(score, 3), "truth_order": truth_order}
