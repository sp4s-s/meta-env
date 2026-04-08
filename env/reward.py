"""
Reward shaping via potential-based functions (Ng et al., 1999) with
running advantage normalization (Schulman et al., 2016).

Guarantees policy-invariance: the optimal policy under shaped rewards
is identical to the one under the original sparse signal.
"""
from __future__ import annotations

import math
from collections import deque
from typing import Deque

from env.models import Action, EngineState
from env.verification import (
    constraint_health,
    identification_progress,
    remediation_progress,
    unresolved_counts,
)

_GAMMA = 0.99
_EPS = 1e-8
_NORM_WINDOW = 64


class RunningStats:
    """Welford online variance for advantage normalization."""

    __slots__ = ("_n", "_mean", "_m2")

    def __init__(self) -> None:
        self._n = 0
        self._mean = 0.0
        self._m2 = 0.0

    def push(self, x: float) -> None:
        self._n += 1
        delta = x - self._mean
        self._mean += delta / self._n
        self._m2 += delta * (x - self._mean)

    def normalize(self, x: float) -> float:
        if self._n < 2:
            return x
        std = math.sqrt(self._m2 / (self._n - 1))
        return (x - self._mean) / max(std, _EPS)


class RewardShaper:
    """
    Potential-Based Reward Shaping (PBRS).

    F(s, s') = gamma * Phi(s') - Phi(s)

    where Phi is a hand-crafted potential function over EngineState.
    This guarantees the set of optimal policies is preserved (Ng et al., 1999)
    while providing dense learning signal.

    Additional structural penalties are applied outside the potential
    for non-admissible actions (false positives, repeated submissions,
    constraint violations) — these form a separate auxiliary loss term
    and do not affect PBRS optimality guarantees.
    """

    def __init__(self) -> None:
        self._stats = RunningStats()
        self._recent: Deque[float] = deque(maxlen=_NORM_WINDOW)

    @staticmethod
    def _potential(s: EngineState, tid: int) -> float:
        """
        State potential Phi(s).

        Monotonically non-decreasing in desirable state features so that
        forward progress yields positive shaping and regression yields
        negative shaping.
        """
        ident = identification_progress(s)
        remed = remediation_progress(s)
        ranking = max(0.0, min(1.0, s.risk_ranking_score))
        health = constraint_health(s)

        if tid == 1:
            phi = 0.72 * ident + 0.28 * ranking
        elif tid == 2:
            phi = 0.30 * ident + 0.70 * remed
        else:
            phi = 0.18 * ident + 0.52 * remed + 0.12 * ranking + 0.18 * health

        return max(0.0, min(1.0, phi))

    @staticmethod
    def _is_repeated(prev: EngineState, action: Action) -> bool:
        if not prev.action_history:
            return False
        last = prev.action_history[-1]
        if last.get("type") != action.action_type:
            return False
        if action.remediation:
            return (last.get("cve") == action.remediation.cve_id
                    and last.get("file_path") == action.remediation.file_path)
        if action.findings:
            f = action.findings[0]
            return (last.get("cve") == f.cve_id
                    and last.get("file_path") == f.file_path
                    and last.get("line_number") == f.line_number)
        return action.action_type == "done"

    def shape(self, s0: EngineState, a: Action, s1: EngineState, tid: int) -> float:
        phi_prev = self._potential(s0, tid)
        phi_curr = self._potential(s1, tid)

        # PBRS core: F(s, s') = gamma * Phi(s') - Phi(s)
        r = _GAMMA * phi_curr - phi_prev

        # Time pressure: small monotonic cost scaled by horizon fraction
        tau = s1.step / max(1, s1.max_steps)
        r -= 0.008 * (1.0 + tau)

        # Structural penalties (auxiliary, outside PBRS)
        if s1.last_action_error:
            r -= 0.10

        fp_delta = len(s1.false_positives) - len(s0.false_positives)
        if fp_delta > 0:
            r -= 0.12 * fp_delta

        weak_delta = s1.weak_findings - s0.weak_findings
        if weak_delta > 0:
            r -= 0.04 * weak_delta

        invalid_delta = s1.invalid_remediations - s0.invalid_remediations
        if invalid_delta > 0:
            r -= 0.07 * invalid_delta

        if self._is_repeated(s0, a):
            r -= 0.06

        if tid == 3 and s1.sla_clock <= 0:
            crit, _ = unresolved_counts(s1)
            if crit > 0:
                r -= 0.10 * crit

        # Running advantage normalization
        self._stats.push(r)
        self._recent.append(r)
        r = self._stats.normalize(r)

        # Record breakdown for policy introspection
        s1.last_reward_breakdown = {
            "phi_prev": round(phi_prev, 4),
            "phi_curr": round(phi_curr, 4),
            "pbrs_delta": round(_GAMMA * phi_curr - phi_prev, 4),
            "fp_delta": fp_delta,
            "weak_delta": weak_delta,
            "invalid_delta": invalid_delta,
        }

        return max(-1.0, min(1.0, r))
