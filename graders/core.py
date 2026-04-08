from __future__ import annotations

from typing import List

from tasks.task_1 import _kt_sim


def n(v: float) -> float:
    return min(max(v, 0.0), 1.0)


def grade_task_1(ground_truth: List[str], identified: List[str],
                 false_positives: int, line_hits: int) -> float:
    """F1 of identification + line accuracy bonus."""
    tp = len(set(identified) & set(ground_truth))
    fp = false_positives
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, len(ground_truth))
    f1 = 2 * precision * recall / max(0.001, precision + recall)
    return n(f1 + 0.1 * line_hits / max(1, tp))


def grade_task_2(init: int, remediated: int, err: int) -> float:
    return n((remediated / init if init > 0 else 0) - min(err * 0.1, 0.4))


def grade_task_3(init: int, res: int, cr: int, hr: int, b: int, sla: int) -> float:
    """Canonical grader for constrained remediation."""
    if cr > 0 or init <= 0:
        return 0.0
    return n(0.55 + 0.15 * (res / init) + (0.1 if hr == 0 else 0) + (0.1 if b > 0 else 0) + (0.1 if sla > 0 else 0))
