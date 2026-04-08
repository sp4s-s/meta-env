from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

try:
    from openenv.core.env_server import Action as OpenEnvAction
    from openenv.core.env_server import Observation as OpenEnvObservation
    from openenv.core.env_server import State as OpenEnvState
except ImportError:
    class OpenEnvAction(BaseModel): pass
    class OpenEnvObservation(BaseModel):
        done: bool = False
        reward: float | None = None
        metadata: Dict[str, Any] = Field(default_factory=dict)
    class OpenEnvState(BaseModel): pass


class CodeFile(BaseModel):
    """A source file presented to the agent."""
    path: str
    content: str
    language: Literal["python", "javascript"]


class GroundTruthEvidence(BaseModel):
    """Verifier-ready evidence for a vulnerable dependency usage site."""
    cve_id: str
    package: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
    cvss_score: float = Field(ge=0.0, le=10.0)
    fixed_version: str = ""
    summary: str = ""
    file_path: str
    language: Literal["python", "javascript"]
    line_numbers: List[int] = Field(default_factory=list)
    code_excerpt: str = ""
    context: str = ""
    incident_source: str = ""


class VulnFinding(BaseModel):
    """Agent's claim about a vulnerability in the code."""
    cve_id: str
    file_path: str
    line_number: int
    package: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
    explanation: str = ""


class RemediationAction(BaseModel):
    """Agent's proposed fix."""
    cve_id: str
    file_path: str
    action: Literal["upgrade", "replace", "remove", "mitigate"]
    target_version: Optional[str] = None
    code_fix: Optional[str] = None  # replacement code snippet
    justification: str = ""


class Action(OpenEnvAction):
    """
    Agent actions for code vulnerability analysis.

    - identify: submit vulnerability findings from code analysis
    - remediate: propose a fix for a found vulnerability
    - rank: prioritize the found vulnerabilities by risk
    - done: signal episode end
    """
    action_type: Literal["identify", "remediate", "rank", "done"]
    findings: Optional[List[VulnFinding]] = None
    remediation: Optional[RemediationAction] = None
    risk_ranking: Optional[List[str]] = None  # ordered CVE IDs
    justification: Optional[str] = None


class Observation(OpenEnvObservation):
    step: int
    max_steps: int
    code_files: List[CodeFile]
    known_vulns: List[str] = Field(default_factory=list)  # CVEs already identified
    task_context: str = ""
    budget_points: int = 0
    sla_clock: int = 0
    info: Dict[str, Any] = Field(default_factory=dict)
    action_history: List[Dict[str, Any]] = Field(default_factory=list)


class Reward(BaseModel):
    value: float = Field(ge=-1.0, le=1.0)
    done: bool
    info: Dict[str, Any] = Field(default_factory=dict)


class EngineState(OpenEnvState):
    episode_id: str
    task_id: int = 1
    step: int = 0
    max_steps: int = 5
    scenario_idx: int = 0

    # Code-centric state
    code_files: List[CodeFile] = Field(default_factory=list)
    ground_truth_vulns: List[str] = Field(default_factory=list)        # actual CVE IDs in code
    ground_truth_lines: Dict[str, List[int]] = Field(default_factory=dict)  # cve_id -> lines
    ground_truth_files: Dict[str, str] = Field(default_factory=dict)   # cve_id -> file path
    ground_truth_fixes: Dict[str, str] = Field(default_factory=dict)   # cve_id -> fix hint
    ground_truth_evidence: Dict[str, GroundTruthEvidence] = Field(default_factory=dict)
    risk_weights: Dict[str, float] = Field(default_factory=dict)
    scenario_context: str = ""

    # Agent progress
    identified_vulns: List[str] = Field(default_factory=list)          # correctly identified
    false_positives: List[str] = Field(default_factory=list)           # wrong claims
    remediated_vulns: List[str] = Field(default_factory=list)          # successfully fixed
    finding_scores: Dict[str, float] = Field(default_factory=dict)
    finding_details: Dict[str, Dict[str, float]] = Field(default_factory=dict)
    remediation_scores: Dict[str, float] = Field(default_factory=dict)
    remediation_details: Dict[str, Dict[str, float]] = Field(default_factory=dict)
    risk_ranking_score: float = 0.0
    weak_findings: int = 0
    invalid_remediations: int = 0

    # Constraints
    budget_points: int = 0
    initial_budget_points: int = 0
    sla_clock: int = 0
    initial_sla_clock: int = 0

    # Bookkeeping
    total_reward: float = 0.0
    done: bool = False
    last_action_error: Optional[str] = None
    last_info: Dict[str, Any] = Field(default_factory=dict)
    last_reward_breakdown: Dict[str, float] = Field(default_factory=dict)
    initial_vuln_count: int = 0
    best_task_score: float = 0.0
    action_history: List[Dict[str, Any]] = Field(default_factory=list)
    difficulty: float = 0.0
