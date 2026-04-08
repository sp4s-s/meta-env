from __future__ import annotations
from typing import Iterable, List
from env.models import CVEInfo
from tasks.task_1 import _kt_sim, _priority

def n(v: float) -> float: return min(max(v, 0.0), 1.0)

def grade_task_1(cves: Iterable[CVEInfo], ranking: List[str]) -> float:
    t = [c.cve_id for c in sorted(cves, key=_priority, reverse=True)]
    return n(_kt_sim(ranking, t))

def grade_task_2(init: int, res: int, err: int) -> float:
    return n((res / init if init > 0 else 0) - min(err * 0.1, 0.4))

def grade_task_3(init: int, res: int, cr: int, hr: int, b: int, sla: int) -> float:
    """Canonical grader for constrained remediation."""
    if cr > 0 or init <= 0: return 0.0
    return n(0.55 + 0.15*(res/init) + (0.1 if hr==0 else 0) + (0.1 if b>0 else 0) + (0.1 if sla>0 else 0))
