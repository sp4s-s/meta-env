"""
Task 3: Constrained Multi-File Remediation (Hard)

Agent receives a multi-file project with multiple vulnerabilities.
Must identify, prioritize, and remediate under budget + SLA constraints.
Critical CVEs MUST be fixed or score is zero.
"""
from __future__ import annotations

from typing import Any, Dict, Tuple

from .task_2 import Task2Handler
from env.models import Action, EngineState
from graders.core import grade_task_3


class Task3Handler(Task2Handler):
    """SLA + budget constrained multi-file remediation."""

    def execute(self, state: EngineState, action: Action) -> Tuple[float, Dict[str, Any]]:
        # Decrement SLA clock each step
        r, info = super().execute(state, action)

        if not state.done:
            return r, info

        # Final grading: critical vulns must all be remediated
        from data.fixtures import FIXTURES
        crit_unresolved = 0
        high_unresolved = 0
        for cve_id in state.ground_truth_vulns:
            if cve_id in state.remediated_vulns:
                continue
            for f in FIXTURES:
                if f["cve_id"] == cve_id:
                    if f["severity"] == "CRITICAL":
                        crit_unresolved += 1
                    elif f["severity"] == "HIGH":
                        high_unresolved += 1

        score = grade_task_3(
            state.initial_vuln_count, len(state.remediated_vulns),
            crit_unresolved, high_unresolved,
            state.budget_points, state.sla_clock,
        )
        info["sc"] = score
        return (score if crit_unresolved == 0 else min(r, 0.0)), info
