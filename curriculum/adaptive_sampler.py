from __future__ import annotations
import random
from typing import List
from data.generator import ScenarioSeed, scenario_bank

class AdaptiveSampler:
    """Thompson Sampling based curriculum. Tracks learning progress per scenario."""
    def __init__(self):
        self.bank = scenario_bank
        self.skill = 0.5
        n = len(self.bank.scenarios)
        self._a = [1.0] * n
        self._b = [1.0] * n
        self._curr = 0
        self._rng = random.Random(2718)

    def _bucket(self, tid: int) -> List[ScenarioSeed]:
        limits = {1: (0, 0.4), 2: (0.3, 0.7), 3: (0.6, 1.0)}.get(tid, (0, 1))
        return [s for s in self.bank.scenarios if limits[0] <= s.difficulty <= limits[1]]

    def sample_scenario(self, tid: int) -> ScenarioSeed:
        pool = self._bucket(tid) or self.bank.scenarios
        best, choice = -1.0, pool[0]
        for s in pool:
            val = self._rng.betavariate(self._a[s.idx], self._b[s.idx])
            prox = max(0.05, 1.0 - abs(s.difficulty - self.skill) * 2.5)
            if val * prox > best:
                best, choice = val * prox, s
        self._curr = choice.idx
        return choice

    def update_skill(self, sc: float):
        sc = max(0.0, min(1.0, sc))
        old = self.skill
        self.skill = 0.8 * self.skill + 0.2 * sc
        if sc > old: self._a[self._curr] += 1
        else: self._b[self._curr] += 1
