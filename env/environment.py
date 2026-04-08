"""
DepVulnEnv — Code-centric RL environment for vulnerability analysis.

The agent receives source code blocks (not package lists) and must:
1. Analyze imports, usage patterns, and call chains
2. Identify which dependencies are vulnerable and WHY
3. Propose remediations with correct fix versions

This forces genuine code reasoning rather than package-name memorization.
"""
from __future__ import annotations

import hashlib
import uuid
from typing import Any, Dict, Optional

try:
    from openenv.core.env_server import Environment as OpenEnvBase
except ImportError:
    class OpenEnvBase: pass

from curriculum.adaptive_sampler import AdaptiveSampler
from data.code_scenarios import CORPUS, CodeScenario, build_composite
from env.reward import RewardShaper
from tasks.task_1 import Task1Handler
from tasks.task_2 import Task2Handler
from tasks.task_3 import Task3Handler
from .models import Action, CodeFile, EngineState, Observation

import random


class DepVulnEnv(OpenEnvBase):
    """
    OpenEnv for dependency vulnerability analysis from source code.

    Task 1 (Easy):   Identify CVEs in a single code file
    Task 2 (Medium): Identify + remediate CVEs under budget
    Task 3 (Hard):   Multi-file project, budget + SLA constraints
    """

    def __init__(self):
        super().__init__()
        self.sampler = AdaptiveSampler()
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
        scenario = self.sampler.sample_scenario(task_id)

        if task_id <= 2:
            # Single code file scenario
            code_files, vulns, lines, files, fixes, context, diff = self._single_file(scenario)
        else:
            # Multi-file composite scenario
            code_files, vulns, lines, files, fixes, context, diff = self._multi_file(scenario)

        max_steps = {1: 5, 2: 10, 3: 20}.get(task_id, 5)
        budget = 0
        if task_id >= 2:
            budget = max(4, len(vulns) * 2)

        self._state = EngineState(
            episode_id=str(uuid.uuid4()),
            task_id=task_id,
            step=0,
            max_steps=max_steps,
            scenario_idx=scenario.idx,
            code_files=code_files,
            ground_truth_vulns=vulns,
            ground_truth_lines=lines,
            ground_truth_files=files,
            ground_truth_fixes=fixes,
            scenario_context=context,
            budget_points=budget,
            sla_clock=max_steps // 2 if task_id == 3 else max_steps,
            initial_vuln_count=len(vulns),
            difficulty=diff,
        )
        return self._build_obs()

    def _single_file(self, scenario) -> tuple:
        """Pick a single code scenario matching difficulty."""
        rng = random.Random(42 + scenario.idx)
        # Filter by difficulty bucket
        pool = [s for s in CORPUS if abs(s.difficulty - scenario.difficulty) < 0.3]
        if not pool:
            pool = CORPUS
        pick: CodeScenario = rng.choice(pool)

        file_path = f"src/main.{'py' if pick.language == 'python' else 'js'}"
        code_files = [CodeFile(
            path=file_path,
            content=pick.code,
            language=pick.language,
        )]
        vulns = list(pick.present_vulns)
        lines = {cve: list(pick.vuln_lines) for cve in pick.present_vulns}
        files = {cve: file_path for cve in pick.present_vulns}
        fixes = {cve: pick.fix_hint for cve in pick.present_vulns}
        return code_files, vulns, lines, files, fixes, pick.context, pick.difficulty

    def _multi_file(self, scenario) -> tuple:
        """Build a composite multi-file project."""
        rng = random.Random(42 + scenario.idx)
        composite = build_composite(CORPUS, n_files=3, rng=rng)

        code_files = []
        all_vulns = []
        all_lines: Dict[str, list] = {}
        all_files: Dict[str, str] = {}
        all_fixes: Dict[str, str] = {}
        contexts = []

        for fname, code in composite["files"].items():
            # Determine language
            lang = "python" if fname.endswith(".py") else "javascript"
            code_files.append(CodeFile(path=fname, content=code, language=lang))

            # Find matching scenario for ground truth
            for sc in CORPUS:
                if sc.code == code:
                    contexts.append(f"{fname}: {sc.context}")
                    for cve in sc.present_vulns:
                        if cve not in all_vulns:
                            all_vulns.append(cve)
                        all_lines[cve] = list(sc.vuln_lines)
                        all_files[cve] = fname
                        all_fixes[cve] = sc.fix_hint
                    break

        context = " | ".join(contexts) if contexts else "Multi-file remediation workspace"
        return code_files, all_vulns, all_lines, all_files, all_fixes, context, composite["difficulty"]

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
        target_cve = action.remediation.cve_id if action.remediation else (
            action.findings[0].cve_id if action.findings else None
        )
        target_path = action.remediation.file_path if action.remediation else (
            action.findings[0].file_path if action.findings else None
        )
        target_line = action.findings[0].line_number if action.findings else None
        reasoning = action.justification or (
            action.remediation.justification if action.remediation else (
                action.findings[0].explanation if action.findings else None
            )
        )
        self._state.action_history.append({
            "step": self._state.step,
            "type": action.action_type,
            "cve": target_cve,
            "file_path": target_path,
            "line_number": target_line,
            "r": round(reward, 4),
            "error": self._state.last_action_error,
            "reasoning": reasoning,
        })

        return self._build_obs(reward)

    def normalized_score(self) -> float:
        if not self._state:
            return 0.0
        s = self._state
        if self._task_id == 1:
            return max(0.0, min(1.0, s.best_task_score))
        identified = len(s.identified_vulns) / max(1, s.initial_vuln_count)
        remediated = len(s.remediated_vulns) / max(1, s.initial_vuln_count)
        fp_penalty = min(0.3, len(s.false_positives) * 0.1)
        return max(0.0, min(1.0, 0.4 * identified + 0.6 * remediated - fp_penalty))

    @property
    def state(self) -> EngineState:
        return self._state

    def close(self):
        self._state = None

    def _build_obs(self, r: float | None = None) -> Observation:
        s = self._state
        # Hash the code for determinism tracking
        code_sig = "".join(f.content[:50] for f in s.code_files)
        h = hashlib.sha256(code_sig.encode()).hexdigest()[:12]

        meta = {
            "h": h,
            "tid": self._task_id,
            "identified": len(s.identified_vulns),
            "remediated": len(s.remediated_vulns),
            "fp": len(s.false_positives),
            "err": s.last_action_error,
            "gt_available": bool(s.ground_truth_vulns),
            "gt_count": len(s.ground_truth_vulns),
            **s.last_info,
        }
        objective = {
            1: "Task 1 evaluates source-level identification and ranking accuracy for vulnerable dependency usage.",
            2: "Task 2 evaluates source-level identification plus remediation quality for vulnerable dependency usage.",
            3: "Task 3 evaluates multi-file remediation quality under budget and SLA constraints.",
        }.get(self._task_id, "Evaluate the current workspace.")
        task_context = objective
        if s.scenario_context:
            task_context = f"{objective} Scenario context: {s.scenario_context}"
        return Observation(
            done=s.done, reward=r, metadata=meta,
            step=s.step, max_steps=s.max_steps,
            code_files=s.code_files,
            known_vulns=s.identified_vulns,
            task_context=task_context,
            budget_points=s.budget_points, sla_clock=s.sla_clock,
            info=meta, action_history=s.action_history,
        )
