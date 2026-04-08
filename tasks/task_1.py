"""
Task 1: Code Vulnerability Identification (Easy)

Agent receives code blocks and must identify which CVEs are present
by analyzing imports, usage patterns, and vulnerable API calls.
Scored by precision/recall of identified CVEs + line-level accuracy.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from .base import TaskHandler
from env.models import Action, EngineState


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
    """Ground truth priority based on fixture data."""
    from data.fixtures import FIXTURES
    for f in FIXTURES:
        if f["cve_id"] == cve_id:
            sev_w = {"CRITICAL": 1.5, "HIGH": 1.2, "MEDIUM": 1.0, "LOW": 0.6, "NONE": 0.3}
            return f["cvss_score"] * sev_w.get(f["severity"], 1.0)
    return 1.0


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
            return state.best_task_score, {"score": state.best_task_score}

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

        truth = set(state.ground_truth_vulns)
        tp, fp, line_hits = 0, 0, 0

        for f in action.findings:
            if f.cve_id in truth:
                if f.cve_id not in state.identified_vulns:
                    state.identified_vulns.append(f.cve_id)
                    tp += 1
                    # Line accuracy bonus
                    if f.cve_id in state.ground_truth_lines:
                        if f.line_number in state.ground_truth_lines[f.cve_id]:
                            line_hits += 1
            else:
                if f.cve_id not in state.false_positives:
                    state.false_positives.append(f.cve_id)
                fp += 1

        # F1 score
        precision = tp / max(1, tp + fp)
        recall = len(state.identified_vulns) / max(1, len(truth))
        f1 = 2 * precision * recall / max(0.001, precision + recall)
        line_bonus = 0.1 * line_hits / max(1, tp)
        score = min(1.0, f1 + line_bonus)
        state.best_task_score = max(state.best_task_score, score)

        return score, {
            "tp": tp, "fp": fp, "recall": round(recall, 3),
            "precision": round(precision, 3), "f1": round(f1, 3),
            "line_hits": line_hits, "score": round(score, 3),
        }

    def _handle_rank(self, state: EngineState, action: Action) -> Tuple[float, Dict[str, Any]]:
        if not action.risk_ranking:
            state.last_action_error = "No ranking submitted"
            return 0.0, {}

        # Ground truth ordering by priority
        truth_order = sorted(state.ground_truth_vulns,
                             key=lambda c: _priority(c, state), reverse=True)
        score = _kt_sim(action.risk_ranking, truth_order)
        state.best_task_score = max(state.best_task_score, score)
        return score, {"ranking_sim": round(score, 3)}
