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
from env.verification import task_completion_score, unresolved_counts


class Task3Handler(Task2Handler):
    """SLA + budget constrained multi-file remediation."""

    def execute(self, state: EngineState, action: Action) -> Tuple[float, Dict[str, Any]]:
        r, info = super().execute(state, action)

        if not state.done:
            return r, info

        crit_unresolved, high_unresolved = unresolved_counts(state)
        score = grade_task_3(
            state.initial_vuln_count, len(state.remediated_vulns),
            crit_unresolved, high_unresolved,
            state.budget_points, state.sla_clock,
        )
        info["sc"] = round(task_completion_score(state, state.task_id), 4)
        info["critical_unresolved"] = crit_unresolved
        info["high_unresolved"] = high_unresolved
        return (score if crit_unresolved == 0 else min(score, 0.0)), info
