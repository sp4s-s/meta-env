"""
DepVulnEnv — code-centric RL environment for vulnerability analysis.

The agent receives source code blocks (not package lists) and must:
1. Analyze imports, usage patterns, and call chains
2. Identify which dependencies are vulnerable and why
3. Propose remediations with correct fix versions

Ground truth extraction uses AST-level import parsing for line precision.
"""
from __future__ import annotations

import hashlib
import random
import uuid
from typing import Any, Dict, Optional

try:
    from openenv.core.env_server import Environment as OpenEnvBase
except ImportError:
    class OpenEnvBase:
        pass

from curriculum.adaptive_sampler import AdaptiveSampler
from data.code_scenarios import CORPUS, CodeScenario, build_composite
from env.reward import RewardShaper
from env.verification import (
    excerpt_for_lines,
    extract_imports,
    risk_weight,
    task_completion_score,
)
from tasks.task_1 import Task1Handler
from tasks.task_2 import Task2Handler
from tasks.task_3 import Task3Handler
from .models import Action, CodeFile, EngineState, GroundTruthEvidence, Observation


class DepVulnEnv(OpenEnvBase):
    """
    OpenEnv for dependency vulnerability analysis from source code.

    Task 1 (Easy):   Identify CVEs in a single code file
    Task 2 (Medium): Identify + remediate CVEs under budget
    Task 3 (Hard):   Multi-file project, budget + SLA constraints
    """

    def __init__(self) -> None:
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
            code_files, evidence_map, context, diff = self._single_file(scenario)
        else:
            code_files, evidence_map, context, diff = self._multi_file(scenario)

        vulns = list(evidence_map)
        lines = {cid: list(ev.line_numbers) for cid, ev in evidence_map.items()}
        files = {cid: ev.file_path for cid, ev in evidence_map.items()}
        fixes = {
            cid: f"Upgrade {ev.package}>={ev.fixed_version}; {ev.summary}"
            for cid, ev in evidence_map.items()
        }
        weights = {cid: risk_weight(ev) for cid, ev in evidence_map.items()}

        max_steps = {1: 5, 2: 10, 3: 20}.get(task_id, 5)
        budget = max(4, len(vulns) * 2) if task_id >= 2 else 0
        sla = max_steps // 2 if task_id == 3 else max_steps

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
            ground_truth_evidence=evidence_map,
            risk_weights=weights,
            scenario_context=context,
            budget_points=budget,
            initial_budget_points=budget,
            sla_clock=sla,
            initial_sla_clock=sla,
            initial_vuln_count=len(vulns),
            difficulty=diff,
        )
        return self._build_obs()

    def _single_file(self, scenario) -> tuple:
        rng = random.Random(42 + scenario.idx)
        pool = [s for s in CORPUS if abs(s.difficulty - scenario.difficulty) < 0.3]
        if not pool:
            pool = CORPUS
        pick: CodeScenario = rng.choice(pool)
        code_files = [CodeFile(path=pick.path, content=pick.code, language=pick.language)]
        evidence_map = {pick.present_vulns[0]: self._make_evidence(pick, pick.path)}
        return code_files, evidence_map, pick.context, pick.difficulty

    def _multi_file(self, scenario) -> tuple:
        rng = random.Random(42 + scenario.idx)
        composite = build_composite(CORPUS, n_files=3, rng=rng)

        code_files = []
        evidence_map: Dict[str, GroundTruthEvidence] = {}
        contexts = []

        for file_path, picked in composite["scenarios"]:
            code_files.append(CodeFile(
                path=file_path, content=picked.code, language=picked.language))
            evidence_map[picked.present_vulns[0]] = self._make_evidence(picked, file_path)
            contexts.append(f"{file_path}: {picked.context}")

        context = " | ".join(contexts) if contexts else "Multi-file remediation workspace"
        return code_files, evidence_map, context, composite["difficulty"]

    def _make_evidence(
        self, scenario: CodeScenario, file_path: str,
    ) -> GroundTruthEvidence:
        # Use AST-based extraction to refine line numbers
        ast_imports = extract_imports(scenario.code, scenario.language)
        pkg_root = scenario.package.split("/")[-1].split("-")[0].lower()
        ast_lines = []
        for mod, mod_lines in ast_imports.items():
            if mod.lower() == pkg_root or pkg_root in mod.lower():
                ast_lines.extend(mod_lines)

        # Prefer AST-extracted lines; fall back to scenario metadata
        lines = sorted(set(ast_lines)) if ast_lines else list(scenario.vuln_lines)

        return GroundTruthEvidence(
            cve_id=scenario.present_vulns[0],
            package=scenario.package,
            severity=scenario.severity,
            cvss_score=scenario.cvss_score,
            fixed_version=scenario.fixed_version,
            summary=scenario.summary,
            file_path=file_path,
            language=scenario.language,
            line_numbers=lines,
            code_excerpt=excerpt_for_lines(scenario.code, lines),
            context=scenario.context,
            incident_source=scenario.incident_source,
        )

    def step(self, action: Action, **kwargs) -> Observation:
        if not self._state or self._state.done:
            return self._build_obs(0.0)

        prev = self._state.model_copy(deep=True)
        self._state.step += 1
        if self._task_id == 3:
            self._state.sla_clock -= 1

        term_reward, info = self._handlers[self._task_id].execute(self._state, action)
        self._state.last_info = info

        if self._state.step >= self._state.max_steps:
            self._state.done = True

        reward = self.reward_shaper.shape(prev, action, self._state, self._task_id)
        if self._state.done:
            reward += term_reward
            self.sampler.update_skill(self.normalized_score())

        reward = max(-1.0, min(1.0, reward))
        self._state.total_reward += reward

        target_cve = (action.remediation.cve_id if action.remediation
                      else (action.findings[0].cve_id if action.findings else None))
        target_path = (action.remediation.file_path if action.remediation
                       else (action.findings[0].file_path if action.findings else None))
        target_line = action.findings[0].line_number if action.findings else None
        reasoning = action.justification or (
            action.remediation.justification if action.remediation
            else (action.findings[0].explanation if action.findings else None))

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
        return task_completion_score(self._state, self._task_id)

    @property
    def state(self) -> EngineState:
        return self._state

    def close(self) -> None:
        self._state = None

    def _build_obs(self, r: float | None = None) -> Observation:
        s = self._state
        code_sig = "".join(f.content[:50] for f in s.code_files)
        h = hashlib.sha256(code_sig.encode()).hexdigest()[:12]

        meta = {
            "h": h,
            "tid": self._task_id,
            "identified": len(s.identified_vulns),
            "remediated": len(s.remediated_vulns),
            "fp": len(s.false_positives),
            "weak": s.weak_findings,
            "invalid_remediation": s.invalid_remediations,
            "ranking_score": round(s.risk_ranking_score, 3),
            "score": round(self.normalized_score(), 3),
            "err": s.last_action_error,
            "gt_available": bool(s.ground_truth_vulns),
            "gt_count": len(s.ground_truth_vulns),
            "reward_breakdown": s.last_reward_breakdown,
            **s.last_info,
        }
        objective = {
            1: "Identify and rank vulnerable dependency usage in source code.",
            2: "Identify vulnerabilities and propose remediations under budget.",
            3: "Multi-file remediation under budget and SLA constraints.",
        }.get(self._task_id, "Evaluate the current workspace.")

        task_ctx = objective
        if s.scenario_context:
            task_ctx = f"{objective} Context: {s.scenario_context}"

        return Observation(
            done=s.done, reward=r, metadata=meta,
            step=s.step, max_steps=s.max_steps,
            code_files=s.code_files,
            known_vulns=s.identified_vulns,
            task_context=task_ctx,
            budget_points=s.budget_points, sla_clock=s.sla_clock,
            info=meta, action_history=s.action_history,
        )
