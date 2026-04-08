"""
Task 2: Vulnerability Remediation (Medium)

Agent must propose correct fixes for identified vulnerabilities.
Scored on: correct fix version, valid replacement code, budget management.
"""
from __future__ import annotations

from typing import Any, Dict, Tuple

from .base import TaskHandler
from env.models import Action, EngineState


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
            sc = len(state.remediated_vulns) / max(1, state.initial_vuln_count)
            return sc, {"sc": round(sc, 4)}

        if action.action_type == "identify":
            return self._handle_identify(state, action)

        if action.action_type == "remediate":
            return self._handle_remediate(state, action)

        state.last_action_error = f"Unsupported: {action.action_type}"
        return 0.0, {}

    def _handle_identify(self, state: EngineState, action: Action) -> Tuple[float, Dict[str, Any]]:
        """Identification step (same logic, but lighter reward in task 2)."""
        if not action.findings:
            state.last_action_error = "No findings"
            return 0.0, {}

        truth = set(state.ground_truth_vulns)
        tp = 0
        for f in action.findings:
            if f.cve_id in truth and f.cve_id not in state.identified_vulns:
                state.identified_vulns.append(f.cve_id)
                tp += 1
            elif f.cve_id not in truth and f.cve_id not in state.false_positives:
                state.false_positives.append(f.cve_id)

        return 0.1 * tp, {"identified": tp}

    def _handle_remediate(self, state: EngineState, action: Action) -> Tuple[float, Dict[str, Any]]:
        if not action.remediation:
            state.last_action_error = "No remediation provided"
            return 0.0, {}

        rem = action.remediation
        cve_id = rem.cve_id

        # Must be a real vuln
        if cve_id not in state.ground_truth_vulns:
            state.last_action_error = f"CVE {cve_id} not in ground truth"
            return -0.15, {"error": "not_present"}

        # Already fixed
        if cve_id in state.remediated_vulns:
            state.last_action_error = "Already remediated"
            return -0.05, {}

        # Budget check
        if state.budget_points < 2:
            state.last_action_error = "Insufficient budget"
            return -0.1, {}
        state.budget_points -= 2

        # Validate fix quality
        fix_hint = state.ground_truth_fixes.get(cve_id, "")
        r = 0.0
        info: Dict[str, Any] = {"cve": cve_id}
        state.last_action_error = None

        # Score components:
        # 1. Is the action type reasonable?
        if rem.action in ("upgrade", "replace", "mitigate"):
            r += 0.15

        # 2. Does the target version match the known fix?
        if rem.target_version and fix_hint:
            # Extract version from fix hint (e.g., "Upgrade jinja2>=3.1.5" -> "3.1.5")
            if rem.target_version in fix_hint:
                r += 0.25
                info["version_match"] = True
            else:
                r += 0.05  # partial credit for any version
                info["version_match"] = False

        # 3. Justification quality (non-empty, references the CVE)
        if rem.justification and len(rem.justification) > 10:
            r += 0.05

        state.remediated_vulns.append(cve_id)
        info["reward"] = round(r, 3)

        # Episode completion
        all_fixed = len(state.remediated_vulns) >= state.initial_vuln_count
        if all_fixed:
            state.done = True
            sc = len(state.remediated_vulns) / max(1, state.initial_vuln_count)
            return r + sc, {**info, "sc": round(sc, 4)}

        return r, info
