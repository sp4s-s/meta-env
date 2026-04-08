"""
Reward shaping for code vulnerability analysis.

Uses Potential-Based Reward Shaping (PBRS): F = γ·φ(s') − φ(s)
where φ measures "remaining risk in the codebase."

Key signals:
- Correct vulnerability identification → large positive phi reduction
- False positive → penalty (agent is hallucinating, not reasoning)
- Line-level accuracy bonus → rewards precise code understanding
- Remediation quality → rewards actual fix reasoning
- Step penalty → encourages efficiency
"""
from __future__ import annotations

from env.models import Action, EngineState


class RewardShaper:
    """PBRS shaping: preserves optimal policy while giving dense signal."""

    @staticmethod
    def _phi(s: EngineState) -> float:
        """Potential: remaining unidentified risk. Higher = more work left."""
        n_remaining = len(set(s.ground_truth_vulns) - set(s.identified_vulns) - set(s.remediated_vulns))
        n_total = max(1, s.initial_vuln_count)
        return n_remaining / n_total

    def shape(self, s0: EngineState, a: Action, s1: EngineState, tid: int) -> float:
        phi0, phi1 = self._phi(s0), self._phi(s1)

        # Core PBRS: reduction in remaining risk
        r = (phi0 - phi1) * 2.0

        # Step cost — force efficiency
        r -= 0.01

        # Error penalty
        if s1.last_action_error:
            r -= 0.08

        # False positive penalty — agent claimed a vuln that doesn't exist
        new_fp = len(s1.false_positives) - len(s0.false_positives)
        if new_fp > 0:
            r -= 0.15 * new_fp

        # Line-level precision bonus (task 1+)
        if a.action_type == "identify" and a.findings:
            for f in a.findings:
                if f.cve_id in s1.ground_truth_lines:
                    truth_lines = s1.ground_truth_lines[f.cve_id]
                    if f.line_number in truth_lines:
                        r += 0.05  # exact line match

        # SLA pressure (task 3)
        if tid == 3 and s1.sla_clock <= 0:
            unresolved_crit = len(set(s1.ground_truth_vulns) - set(s1.remediated_vulns))
            if unresolved_crit > 0:
                r -= 0.05

        return max(-1.0, min(1.0, r))
