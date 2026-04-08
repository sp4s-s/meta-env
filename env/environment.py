from __future__ import annotations

import hashlib
import uuid
from typing import Any, Dict, Optional

try:
    from openenv.core.env_server import Environment as OpenEnvBase
except ImportError:
    class OpenEnvBase: pass

from curriculum.adaptive_sampler import AdaptiveSampler
from data.generator import ScenarioGenerator
from env.reward import RewardShaper
from tasks.task_1 import Task1Handler
from tasks.task_2 import Task2Handler
from tasks.task_3 import Task3Handler
from .models import Action, CVEInfo, EngineState, NodeInfo, Observation, Reward

class DepVulnEnv(OpenEnvBase):
    """
    OpenEnv for dependency vulnerability management.
    Models the CVE triage pipeline: identification, prioritisation, and remediation.
    """
    def __init__(self):
        super().__init__()
        self.sampler = AdaptiveSampler()
        self.generator = ScenarioGenerator()
        self.reward_shaper = RewardShaper()
        self._state: Optional[EngineState] = None
        self._task_id = 1
        self._handlers = {
            1: Task1Handler(),
            2: Task2Handler(),
            3: Task3Handler(),
        }

    def reset(self, task_id: int = 1) -> Observation:
        self._task_id = task_id
        seed = self.sampler.sample_scenario(task_id)
        nodes, cves = self.generator.generate_graph(seed)
        
        # Scenario config logic
        max_steps = {1: 5, 2: 10, 3: 20}.get(task_id, 5)
        budget = 0
        if task_id == 2:
            budget = max(2, len(cves) * 2)
        elif task_id == 3:
            budget = max(3, len([c for c in cves if c["severity"] in ("CRITICAL", "HIGH")]) * 2)
            
        self._state = EngineState(
            episode_id=str(uuid.uuid4()),
            task_id=task_id,
            step=0,
            max_steps=max_steps,
            scenario_idx=seed.idx,
            graph=[NodeInfo(**n) for n in nodes],
            active_cves=[CVEInfo(**c) for c in cves],
            budget_points=budget,
            sla_clock=max_steps // 2 if task_id == 3 else max_steps,
            initial_cve_count=len(cves)
        )
        return self._build_obs()

    def step(self, action: Action, **kwargs) -> Observation:
        if not self._state or self._state.done:
            return self._build_obs(0.0)

        prev = self._state.model_copy(deep=True)
        self._state.step += 1
        if self._task_id == 3:
            self._state.sla_clock -= 1

        term_reward, info = self._handlers[self._task_id].execute(self._state, action)
        
        if self._state.step >= self._state.max_steps:
            self._state.done = True

        reward = self.reward_shaper.shape(prev, action, self._state, self._task_id)
        if self._state.done:
            reward += term_reward
            self.sampler.update_skill(self.normalized_score())

        reward = max(-1.0, min(1.0, reward))
        self._state.total_reward += reward
        self._state.last_info = info
        self._state.action_history.append({
            "step": self._state.step,
            "type": action.action_type,
            "cve": action.cve_id,
            "r": round(reward, 4)
        })

        return self._build_obs(reward)

    def normalized_score(self) -> float:
        if not self._state: return 0.0
        if self._task_id == 1:
            return max(0.0, min(1.0, self._state.best_task_score))
        return max(0.0, min(1.0, len(self._state.resolved_cves) / max(1, self._state.initial_cve_count)))

    @property
    def state(self) -> EngineState:
        return self._state

    def close(self):
        self._state = None

    def _build_obs(self, r: float | None = None) -> Observation:
        s = self._state
        g_sig = "".join(f"{n.name}:{n.version}" for n in sorted(s.graph, key=lambda x: x.name))
        h = hashlib.sha256(g_sig.encode()).hexdigest()[:12]
        
        meta = {
            "h": h,
            "tid": self._task_id,
            "res": len(s.resolved_cves),
            "err": s.last_action_error,
            **s.last_info
        }
        return Observation(
            done=s.done, reward=r, metadata=meta,
            step=s.step, max_steps=s.max_steps,
            graph=s.graph, active_cves=s.active_cves,
            budget_points=s.budget_points, sla_clock=s.sla_clock,
            info=meta, action_history=s.action_history
        )
