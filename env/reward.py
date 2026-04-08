from __future__ import annotations
from env.models import Action, EngineState

class RewardShaper:
    """PBRS shaping function: F = g*phi(s') - phi(s). Preserves optimal policy."""
    @staticmethod
    def _phi(s: EngineState) -> float:
        d = 0.0
        for c in s.active_cves:
            b = 1.25 if c.severity == "CRITICAL" else 1.0
            if c.kev_listed: b *= 1.75
            if c.vex_status == "not_affected": b *= 0.1
            ssvc = {"act": 1.5, "attend": 1.2, "track*": 1.0, "track": 0.8}.get(c.ssvc_decision, 1.0)
            eps = max(c.epss_score, c.epss_percentile, 0.05)
            d += (b * ssvc * c.cvss_score * eps) / max(1.0, float(c.reachability_depth))
        return d

    def shape(self, s0: EngineState, a: Action, s1: EngineState, tid: int) -> float:
        phi0, phi1 = self._phi(s0), self._phi(s1)
        r = (phi0 - phi1) / max(1.0, phi0 + 1.0)
        r -= 0.01 # Step penalty
        if s1.last_action_error: r -= 0.08
        elif a.action_type in ("accept", "suppress"): r -= 0.01
        if tid == 3 and s1.sla_clock <= 0 and any(c.severity == "CRITICAL" for c in s1.active_cves):
            r -= 0.05
        return max(-1.0, min(1.0, r))
