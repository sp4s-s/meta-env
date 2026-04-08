from __future__ import annotations
from typing import Any, Dict, Tuple
from .base import TaskHandler
from env.models import Action, EngineState

class Task2Handler(TaskHandler):
    def _resolve(self, state: EngineState, cid: str, b: str):
        if b: getattr(state, f"{b}_cves").append(cid)
        state.resolved_cves.append(cid)
        state.active_cves = [c for c in state.active_cves if c.cve_id != cid]

    def execute(self, state: EngineState, action: Action) -> Tuple[float, Dict[str, Any]]:
        if action.action_type == "done":
            state.done = True
            sc = len(state.resolved_cves) / max(1, state.initial_cve_count)
            return sc, {"sc": sc}

        if action.action_type not in ("fix", "suppress", "accept"):
            state.last_action_error = f"Unsupported op: {action.action_type}"
            return 0.0, {}

        cve = next((c for c in state.active_cves if c.cve_id == action.cve_id), None)
        if not cve:
            state.last_action_error = "CVE not found"
            return 0.0, {}

        r, info = 0.0, {"cid": cve.cve_id}
        state.last_action_error = None

        if action.action_type == "fix":
            if state.budget_points < 2:
                state.last_action_error = "OOB budget"
                return -0.1, {}
            state.budget_points -= 2
            if action.target_node == cve.target_node and action.target_version == cve.fixed_version:
                r = 0.45
                self._resolve(state, cve.cve_id, "")
            else:
                r, state.last_action_error = -0.15, "Invalid fix config"

        elif action.action_type == "suppress":
            if cve.severity in ("LOW", "NONE") or cve.reachability_depth >= 2:
                r = 0.18
                self._resolve(state, cve.cve_id, "suppressed")
            else:
                r, state.last_action_error = -0.25, "Ineligible for suppression"

        elif action.action_type == "accept":
            if cve.severity in ("MEDIUM", "LOW", "NONE"):
                r = 0.08
                self._resolve(state, cve.cve_id, "accepted")
            else:
                r, state.last_action_error = -0.2, "Risk too high for acceptance"

        if not state.active_cves: state.done = True
        if state.done:
            sc = len(state.resolved_cves) / max(1, state.initial_cve_count)
            info["sc"] = round(sc, 4)
            return r + sc, info

        return r, info
