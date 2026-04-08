from __future__ import annotations
from typing import Any, Dict, Tuple
from env.models import Action, EngineState
from graders.core import grade_task_3
from .task_2 import Task2Handler

class Task3Handler(Task2Handler):
    """SLA and Budget constrained remediation."""
    def execute(self, state: EngineState, action: Action) -> Tuple[float, Dict[str, Any]]:
        r, info = super().execute(state, action)
        if not state.done: return r, info

        crits = sum(1 for c in state.active_cves if c.severity == "CRITICAL")
        highs = sum(1 for c in state.active_cves if c.severity == "HIGH")

        score = grade_task_3(
            state.initial_cve_count, len(state.resolved_cves),
            crits, highs, state.budget_points, state.sla_clock
        )
        info["sc"] = score
        return (score if crits == 0 else min(r, 0.0)), info
