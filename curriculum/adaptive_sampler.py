"""
Thompson Sampling curriculum — selects code scenarios by difficulty bracket.
"""
from __future__ import annotations

import random
from collections import deque
from dataclasses import dataclass
from typing import List

from data.code_scenarios import CORPUS, CodeScenario


@dataclass(frozen=True)
class ScenarioSlot:
    """Lightweight reference used by the sampler."""
    idx: int
    difficulty: float


class AdaptiveSampler:
    """Thompson Sampling based curriculum over code scenarios."""

    def __init__(self):
        self.slots = [ScenarioSlot(idx=s.idx, difficulty=s.difficulty) for s in CORPUS]
        self.skill = 0.5
        n = len(self.slots)
        self._a = [1.0] * n
        self._b = [1.0] * n
        self._seen = [0] * n
        self._curr = 0
        self._curr_difficulty = 0.5
        self._rng = random.Random(2718)
        self._recent = deque(maxlen=8)

    def _bucket(self, tid: int) -> List[ScenarioSlot]:
        limits = {1: (0, 0.45), 2: (0.25, 0.65), 3: (0.45, 1.0)}.get(tid, (0, 1))
        return [s for s in self.slots if limits[0] <= s.difficulty <= limits[1]]

    def sample_scenario(self, tid: int) -> ScenarioSlot:
        pool = self._bucket(tid) or self.slots
        lower, upper = {1: (0.0, 0.45), 2: (0.25, 0.65), 3: (0.45, 1.0)}.get(tid, (0.0, 1.0))
        span = max(0.15, upper - lower)
        target = min(upper, max(lower, (lower + upper) / 2 + (self.skill - 0.5) * 0.35))
        best, choice = -1.0, pool[0]
        for s in pool:
            posterior = self._rng.betavariate(self._a[s.idx], self._b[s.idx])
            alpha = self._a[s.idx]
            beta = self._b[s.idx]
            uncertainty = (alpha * beta) / (((alpha + beta) ** 2) * (alpha + beta + 1))
            difficulty_fit = max(0.12, 1.0 - abs(s.difficulty - target) / span)
            novelty = 0.72 if s.idx in self._recent else 1.0
            exposure = 1.0 / (1.0 + 0.08 * self._seen[s.idx])
            score = (0.55 * posterior + 0.2 * uncertainty + 0.25 * difficulty_fit) * novelty * exposure
            if score > best:
                best, choice = score, s
        self._curr = choice.idx
        self._curr_difficulty = choice.difficulty
        self._seen[choice.idx] += 1
        self._recent.append(choice.idx)
        return choice

    def update_skill(self, sc: float):
        sc = max(0.0, min(1.0, sc))
        margin = sc - self._curr_difficulty
        self.skill = 0.75 * self.skill + 0.25 * sc
        if margin >= 0:
            self._a[self._curr] += 1.0 + min(1.5, margin * 2.0)
        else:
            self._b[self._curr] += 1.0 + min(1.5, abs(margin) * 2.0)
