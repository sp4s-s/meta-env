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

class CVEInfo(BaseModel):
    cve_id: str
    target_node: str
    cvss_score: float = Field(ge=0.0, le=10.0)
    epss_score: float = Field(ge=0.0, le=1.0)
    epss_percentile: float = Field(ge=0.0, le=1.0, default=0.0)
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
    reachability_depth: int = Field(ge=0)
    kev_listed: bool = False
    vex_status: Literal["affected", "not_affected", "fixed", "under_investigation"] = "affected"
    ssvc_decision: Literal["track", "track*", "attend", "act"] = "track"
    fixed_version: Optional[str] = None
    summary: str = ""
    ecosystem: str = "PyPI"
    package: str = ""

class NodeInfo(BaseModel):
    name: str
    version: str
    depth: int = Field(ge=0)
    direct: bool
    dependencies: List[str] = Field(default_factory=list)
    cves: List[str] = Field(default_factory=list)
    ecosystem: str = "PyPI"

class Observation(OpenEnvObservation):
    step: int
    max_steps: int
    graph: List[NodeInfo]
    active_cves: List[CVEInfo]
    budget_points: int
    sla_clock: int
    info: Dict[str, Any]
    action_history: List[Dict[str, Any]]

class Action(OpenEnvAction):
    action_type: Literal["rank", "fix", "suppress", "accept", "done"]
    cve_rankings: Optional[List[str]] = None
    cve_id: Optional[str] = None
    target_node: Optional[str] = None
    target_version: Optional[str] = None
    justification: Optional[str] = None

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
    graph: List[NodeInfo] = Field(default_factory=list)
    active_cves: List[CVEInfo] = Field(default_factory=list)
    budget_points: int = 0
    sla_clock: int = 0
    resolved_cves: List[str] = Field(default_factory=list)
    accepted_cves: List[str] = Field(default_factory=list)
    suppressed_cves: List[str] = Field(default_factory=list)
    total_reward: float = 0.0
    done: bool = False
    last_action_error: Optional[str] = None
    last_info: Dict[str, Any] = Field(default_factory=dict)
    initial_cve_count: int = 0
    best_task_score: float = 0.0
    action_history: List[Dict[str, Any]] = Field(default_factory=list)
