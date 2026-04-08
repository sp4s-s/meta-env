"""
Task graders — canonical scoring functions referenced by openenv.yaml.

Each grader is a pure function: state in, float [0,1] out.
These are the ground-truth evaluation functions used for leaderboard
ranking; the reward shaper is a *separate* training signal.
"""
from __future__ import annotations

from typing import List


def _clamp(v: float) -> float:
    return min(max(v, 0.0), 1.0)


def grade_task_1(
    ground_truth: List[str],
    identified: List[str],
    false_positives: int,
    line_hits: int,
) -> float:
    """F1 of CVE identification with line-accuracy bonus."""
    tp = len(set(identified) & set(ground_truth))
    fp = false_positives
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, len(ground_truth))
    f1 = 2 * precision * recall / max(1e-6, precision + recall)
    line_bonus = 0.1 * (line_hits / max(1, tp)) if tp > 0 else 0.0
    return _clamp(f1 + line_bonus)


def grade_task_2(
    initial_count: int,
    remediated_count: int,
    error_count: int,
) -> float:
    """Fraction remediated, penalized by invalid attempts."""
    if initial_count <= 0:
        return 0.0
    base = remediated_count / initial_count
    penalty = min(error_count * 0.1, 0.4)
    return _clamp(base - penalty)


def grade_task_3(
    initial_count: int,
    remediated_count: int,
    critical_remaining: int,
    high_remaining: int,
    budget_remaining: int,
    sla_remaining: int,
) -> float:
    """Constrained remediation: zero if any critical CVE unresolved."""
    if critical_remaining > 0 or initial_count <= 0:
        return 0.0
    progress = remediated_count / initial_count
    return _clamp(
        0.55
        + 0.15 * progress
        + (0.1 if high_remaining == 0 else 0.0)
        + (0.1 if budget_remaining > 0 else 0.0)
        + (0.1 if sla_remaining > 0 else 0.0)
    )
