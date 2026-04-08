from abc import ABC, abstractmethod
from typing import Any, Dict, Tuple

from env.models import Action, EngineState, RemediationAction, VulnFinding
from env.verification import (
    FINDING_ACCEPT_THRESHOLD,
    REMEDIATION_ACCEPT_THRESHOLD,
    finding_match_components,
    remediation_match_components,
)


def apply_identification(state: EngineState, findings: list[VulnFinding]) -> Dict[str, Any]:
    accepted = 0
    partial = 0
    false_positives = 0
    exact_lines = 0
    evidence_gain = 0.0
    state.last_action_error = None

    for finding in findings:
        evidence = state.ground_truth_evidence.get(finding.cve_id)
        if evidence is None:
            false_positives += 1
            if finding.cve_id not in state.false_positives:
                state.false_positives.append(finding.cve_id)
            continue

        components = finding_match_components(finding, evidence)
        previous = state.finding_scores.get(finding.cve_id, 0.0)
        if components["score"] > previous:
            state.finding_scores[finding.cve_id] = components["score"]
            state.finding_details[finding.cve_id] = components
            evidence_gain += components["score"] - previous
        if components["score"] >= FINDING_ACCEPT_THRESHOLD:
            if finding.cve_id not in state.identified_vulns:
                state.identified_vulns.append(finding.cve_id)
                accepted += 1
        elif components["score"] > previous:
            partial += 1
            state.weak_findings += 1
        if components["line"] >= 0.999:
            exact_lines += 1

    return {
        "accepted": accepted,
        "partial": partial,
        "fp": false_positives,
        "line_hits": exact_lines,
        "evidence_gain": round(evidence_gain, 4),
    }


def apply_remediation(state: EngineState, remediation: RemediationAction) -> Dict[str, Any]:
    evidence = state.ground_truth_evidence.get(remediation.cve_id)
    if evidence is None:
        state.invalid_remediations += 1
        state.last_action_error = f"CVE {remediation.cve_id} not in ground truth"
        return {"error": "not_present"}

    components = remediation_match_components(remediation, evidence)
    previous = state.remediation_scores.get(remediation.cve_id, 0.0)
    if components["score"] > previous:
        state.remediation_scores[remediation.cve_id] = components["score"]
        state.remediation_details[remediation.cve_id] = components
    if components["score"] >= REMEDIATION_ACCEPT_THRESHOLD and remediation.cve_id not in state.remediated_vulns:
        state.remediated_vulns.append(remediation.cve_id)
    elif components["score"] < REMEDIATION_ACCEPT_THRESHOLD:
        state.invalid_remediations += 1
    state.last_action_error = None if components["score"] >= 0.35 else "Remediation is not sufficiently grounded"
    return {
        "quality": round(components["score"], 4),
        "version_match": components["version"] >= 0.999,
        "accepted": remediation.cve_id in state.remediated_vulns,
        **{key: round(value, 4) for key, value in components.items()},
    }

class TaskHandler(ABC):
    @abstractmethod
    def execute(self, state: EngineState, action: Action) -> Tuple[float, Dict[str, Any]]:
        """
        Executes the action on the state. 
        Returns (terminal_reward, info_dict).
        Terminal reward should be > 0.0 only if state.done is True and task is successful.
        """
        pass
