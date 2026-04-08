"""
Task 2: Vulnerability Remediation (Medium)

Agent must propose correct fixes for identified vulnerabilities.
Scored on: correct fix version, valid replacement code, budget management.
"""
from __future__ import annotations

from typing import Any, Dict, Tuple

from .base import TaskHandler, apply_identification, apply_remediation
from env.models import Action, EngineState
from env.verification import task_completion_score


class Task2Handler(TaskHandler):
    """
    Remediation task: agent proposes fixes for code vulnerabilities.

    Actions:
    - identify: find vulns first (same as task 1)
    - remediate: propose a fix for a specific CVE
    - done: end episode

    Scoring: fraction of vulns correctly remediated, minus budget overruns.
    """

    def execute(self, state: EngineState, action: Action) -> Tuple[float, Dict[str, Any]]:
        if action.action_type == "done":
            state.done = True
            sc = task_completion_score(state, state.task_id)
            return sc, {"sc": round(sc, 4)}

        if action.action_type == "identify":
            return self._handle_identify(state, action)

        if action.action_type == "remediate":
            return self._handle_remediate(state, action)

        state.last_action_error = f"Unsupported: {action.action_type}"
        return 0.0, {}

    def _handle_identify(self, state: EngineState, action: Action) -> Tuple[float, Dict[str, Any]]:
        if not action.findings:
            state.last_action_error = "No findings"
            return 0.0, {}

        info = apply_identification(state, action.findings)
        return task_completion_score(state, state.task_id), {
            "identified": info["accepted"],
            "partial": info["partial"],
            "fp": info["fp"],
            "evidence_gain": info["evidence_gain"],
        }

    def _handle_remediate(self, state: EngineState, action: Action) -> Tuple[float, Dict[str, Any]]:
        if not action.remediation:
            state.last_action_error = "No remediation provided"
            return 0.0, {}

        rem = action.remediation
        cve_id = rem.cve_id

        if cve_id not in state.ground_truth_vulns:
            state.invalid_remediations += 1
            state.last_action_error = f"CVE {cve_id} not in ground truth"
            return -0.15, {"error": "not_present"}

        if cve_id in state.remediated_vulns:
            state.last_action_error = "Already remediated"
            return -0.05, {}

        if state.budget_points < 2:
            state.invalid_remediations += 1
            state.last_action_error = "Insufficient budget"
            return -0.1, {}
        state.budget_points -= 2

        info = {"cve": cve_id, **apply_remediation(state, rem)}

        all_fixed = len(state.remediated_vulns) >= state.initial_vuln_count
        if all_fixed:
            state.done = True
            sc = task_completion_score(state, state.task_id)
            return sc, {**info, "sc": round(sc, 4)}

        return task_completion_score(state, state.task_id), info
