"""
Ground truth verification with AST-aware import resolution
and multi-signal evidence scoring.

Evidence extraction follows the VerIF methodology (Peng et al., 2025):
deterministic structural checks over code artifacts rather than
semantic similarity, ensuring reproducible and auditable grading.
"""
from __future__ import annotations

import ast
import math
import re
from typing import Dict, Iterable, List, Sequence, Set

from env.models import EngineState, GroundTruthEvidence, RemediationAction, VulnFinding

FINDING_ACCEPT_THRESHOLD = 0.62
REMEDIATION_ACCEPT_THRESHOLD = 0.72

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
_SEVERITY_BASE = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.55, "LOW": 0.3, "NONE": 0.12}

_TOKEN_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9_]{2,}")
_STOPWORDS: Set[str] = frozenset({
    "this", "that", "with", "from", "into", "before", "after", "while",
    "using", "uses", "user", "input", "request", "response", "code",
    "path", "data", "load", "loads", "open", "opens", "service",
    "worker", "template", "runtime", "directly", "through", "external",
    "payload", "attack", "attacker", "controlled", "vulnerable",
    "dependency", "version", "upgrade",
})


def clamp(value: float, lower: float = 0.0, upper: float = 1.0) -> float:
    return max(lower, min(upper, value))


def normalize_text(value: str | None) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


# ── AST-Level Import Extraction ─────────────────────────────────────

def extract_python_imports(code: str) -> Dict[str, List[int]]:
    """Parse Python source and return {module_name: [line_numbers]}.

    Uses the ast module for precise extraction. Falls back to regex
    if the source contains syntax errors.
    """
    result: Dict[str, List[int]] = {}
    try:
        tree = ast.parse(code)
    except SyntaxError:
        for i, line in enumerate(code.splitlines(), 1):
            m = re.match(r"^\s*(?:from|import)\s+([A-Za-z_][A-Za-z0-9_.]*)", line)
            if m:
                mod = m.group(1).split(".")[0]
                result.setdefault(mod, []).append(i)
        return result

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mod = alias.name.split(".")[0]
                result.setdefault(mod, []).append(node.lineno)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                mod = node.module.split(".")[0]
                result.setdefault(mod, []).append(node.lineno)
    return result


def extract_js_requires(code: str) -> Dict[str, List[int]]:
    """Extract CommonJS require() and ES import statements."""
    result: Dict[str, List[int]] = {}
    for i, line in enumerate(code.splitlines(), 1):
        for m in re.finditer(r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)""", line):
            result.setdefault(m.group(1), []).append(i)
        for m in re.finditer(r"""(?:from|import)\s+['"]([^'"]+)['"]""", line):
            result.setdefault(m.group(1), []).append(i)
    return result


def extract_imports(code: str, language: str) -> Dict[str, List[int]]:
    if language == "python":
        return extract_python_imports(code)
    return extract_js_requires(code)


# ── Token / Keyword Extraction ──────────────────────────────────────

def _identifier_tokens(value: str) -> List[str]:
    return [t.lower() for t in _TOKEN_RE.findall(value)]


def evidence_keywords(evidence: GroundTruthEvidence) -> List[str]:
    tokens: List[str] = []
    for field in (evidence.package, evidence.cve_id, evidence.summary,
                  evidence.context, evidence.code_excerpt):
        for t in _identifier_tokens(field):
            if t not in _STOPWORDS:
                tokens.append(t)
    seen: Set[str] = set()
    ordered: List[str] = []
    for t in tokens:
        if t not in seen:
            ordered.append(t)
            seen.add(t)
    return ordered[:8]


# ── Excerpt & Weight Helpers ────────────────────────────────────────

def excerpt_for_lines(code: str, lines: Sequence[int], radius: int = 1) -> str:
    if not lines:
        return ""
    all_lines = code.splitlines()
    start = max(1, min(lines) - radius)
    end = min(len(all_lines), max(lines) + radius)
    return "\n".join(
        ln.strip() for ln in (all_lines[i - 1] for i in range(start, end + 1)) if ln.strip()
    )


def risk_weight(evidence: GroundTruthEvidence) -> float:
    severity = _SEVERITY_BASE.get(evidence.severity, 0.25)
    cvss = clamp(evidence.cvss_score / 10.0)
    return round(clamp(0.55 * severity + 0.45 * cvss, 0.1, 1.0), 4)


def weighted_progress(
    values: Dict[str, float],
    weights: Dict[str, float],
    keys: Iterable[str],
) -> float:
    keys = list(keys)
    total = sum(weights.get(k, 1.0) for k in keys)
    if total <= 0:
        return 0.0
    score = sum(weights.get(k, 1.0) * clamp(values.get(k, 0.0)) for k in keys)
    return clamp(score / total)


# ── Component Matchers ──────────────────────────────────────────────

def file_match_score(candidate: str | None, expected: str) -> float:
    cand = normalize_text(candidate)
    truth = normalize_text(expected)
    if not cand or not truth:
        return 0.0
    if cand == truth:
        return 1.0

    cand_parts = cand.strip("/").split("/")
    truth_parts = truth.strip("/").split("/")

    if cand_parts[-1] == truth_parts[-1]:
        overlap = 0
        for cp, tp in zip(reversed(cand_parts), reversed(truth_parts)):
            if cp == tp:
                overlap += 1
            else:
                break
        depth = max(len(cand_parts), len(truth_parts))
        return clamp(0.55 + 0.45 * (overlap / depth))

    if cand.endswith(truth_parts[-1]) or truth.endswith(cand_parts[-1]):
        return 0.4
    return 0.0


def package_match_score(candidate: str | None, expected: str) -> float:
    cand = normalize_text(candidate)
    truth = normalize_text(expected)
    if not cand or not truth:
        return 0.0
    if cand == truth:
        return 1.0
    if cand.split("/")[-1] == truth.split("/")[-1]:
        return 0.75
    return 0.0


def severity_match_score(candidate: str | None, expected: str) -> float:
    cand = (candidate or "").upper()
    truth = expected.upper()
    if not cand:
        return 0.0
    if cand == truth:
        return 1.0
    gap = abs(_SEVERITY_ORDER.get(cand, 0) - _SEVERITY_ORDER.get(truth, 0))
    return {1: 0.6, 2: 0.25}.get(gap, 0.0)


def line_match_score(candidate: int | None, truth_lines: Sequence[int]) -> float:
    if candidate is None or candidate <= 0 or not truth_lines:
        return 0.0
    delta = min(abs(candidate - ln) for ln in truth_lines)
    if delta == 0:
        return 1.0
    # Exponential decay: proximity-weighted relevance
    return clamp(math.exp(-0.35 * delta))


def grounding_score(
    text: str | None,
    evidence: GroundTruthEvidence,
    *,
    include_version: bool = False,
) -> float:
    body = normalize_text(text)
    if not body:
        return 0.0

    score = 0.0
    body_tokens = set(_identifier_tokens(body))

    if normalize_text(evidence.package) in body:
        score += 0.35
    if normalize_text(evidence.cve_id) in body:
        score += 0.35
    if include_version and evidence.fixed_version:
        if normalize_text(evidence.fixed_version) in body:
            score += 0.15

    kw = set(evidence_keywords(evidence))
    if kw and body_tokens:
        score += 0.15 * len(kw & body_tokens) / len(kw)

    return clamp(score)


# ── Finding/Remediation Composite Scores ────────────────────────────

def finding_match_components(
    finding: VulnFinding, evidence: GroundTruthEvidence,
) -> Dict[str, float]:
    zero = {"score": 0.0, "file": 0.0, "line": 0.0, "package": 0.0,
            "severity": 0.0, "explanation": 0.0}
    if finding.cve_id != evidence.cve_id:
        return zero

    c = {
        "file": file_match_score(finding.file_path, evidence.file_path),
        "line": line_match_score(finding.line_number, evidence.line_numbers),
        "package": package_match_score(finding.package, evidence.package),
        "severity": severity_match_score(finding.severity, evidence.severity),
        "explanation": grounding_score(finding.explanation, evidence),
    }
    w = {"file": 0.28, "line": 0.32, "package": 0.18, "severity": 0.08, "explanation": 0.14}
    c["score"] = clamp(sum(w[k] * c[k] for k in w))
    return c


def _version_parts(version: str | None) -> list:
    if not version:
        return []
    cleaned = re.sub(r"^[<>=~^v\s]+", "", version.strip())
    parts: list = []
    for tok in re.split(r"[.\-+_]", cleaned):
        if not tok:
            continue
        if tok.isdigit():
            parts.append(int(tok))
        else:
            m = re.match(r"(\d+)([a-z]+)", tok, re.IGNORECASE)
            if m:
                parts.append(int(m.group(1)))
                parts.append(m.group(2).lower())
            else:
                parts.append(tok.lower())
    return parts


def version_at_least(candidate: str | None, minimum: str | None) -> bool:
    cp = _version_parts(candidate)
    mp = _version_parts(minimum)
    if not cp or not mp:
        return False
    width = max(len(cp), len(mp))
    for i in range(width):
        c = cp[i] if i < len(cp) else 0
        m = mp[i] if i < len(mp) else 0
        if c == m:
            continue
        if isinstance(c, int) and isinstance(m, int):
            return c > m
        return str(c) > str(m)
    return True


def remediation_match_components(
    remediation: RemediationAction, evidence: GroundTruthEvidence,
) -> Dict[str, float]:
    zero = {"score": 0.0, "file": 0.0, "action": 0.0, "version": 0.0,
            "justification": 0.0, "code_fix": 0.0}
    if remediation.cve_id != evidence.cve_id:
        return zero

    action_score = {"upgrade": 1.0, "replace": 0.82, "remove": 0.74,
                    "mitigate": 0.58}.get(remediation.action, 0.0)

    version_score = 0.0
    if evidence.fixed_version:
        if version_at_least(remediation.target_version, evidence.fixed_version):
            version_score = 1.0
        elif remediation.target_version:
            version_score = 0.18

    justification = grounding_score(
        remediation.justification, evidence, include_version=True)
    code_fix = (grounding_score(remediation.code_fix, evidence, include_version=True)
                if remediation.code_fix else 0.0)

    c = {
        "file": file_match_score(remediation.file_path, evidence.file_path),
        "action": action_score,
        "version": version_score,
        "justification": justification,
        "code_fix": code_fix,
    }
    w = {"file": 0.16, "action": 0.2, "version": 0.42,
         "justification": 0.16, "code_fix": 0.06}
    if not evidence.fixed_version:
        w = {"file": 0.16, "action": 0.2, "version": 0.18,
             "justification": 0.26, "code_fix": 0.2}

    c["score"] = clamp(sum(w[k] * c[k] for k in w))
    return c


# ── Ranking (nDCG) ──────────────────────────────────────────────────

def weighted_ranking_score(
    ranking: Sequence[str] | None,
    evidence_map: Dict[str, GroundTruthEvidence],
) -> float:
    if not ranking or not evidence_map:
        return 0.0
    w = {cid: risk_weight(ev) for cid, ev in evidence_map.items()}
    ordered, seen = [], set()
    for cid in ranking:
        if cid in w and cid not in seen:
            ordered.append(cid)
            seen.add(cid)
    if not ordered:
        return 0.0
    dcg = sum(w[c] / math.log2(i + 2) for i, c in enumerate(ordered))
    ideal = sorted(w, key=w.get, reverse=True)
    idcg = sum(w[c] / math.log2(i + 2) for i, c in enumerate(ideal))
    coverage = sum(w[c] for c in ordered) / max(1e-6, sum(w.values()))
    return clamp(0.85 * (dcg / max(idcg, 1e-6)) + 0.15 * coverage)


# ── Progress Aggregators ────────────────────────────────────────────

def identification_progress(state: EngineState) -> float:
    coverage = weighted_progress(
        state.finding_scores, state.risk_weights, state.ground_truth_vulns)
    line_quality = weighted_progress(
        {cid: d.get("line", 0.0) for cid, d in state.finding_details.items()},
        state.risk_weights, state.ground_truth_vulns)
    n_id = len(state.identified_vulns)
    precision = n_id / max(1, n_id + len(state.false_positives))
    return clamp(0.55 * coverage + 0.25 * line_quality + 0.2 * precision)


def remediation_progress(state: EngineState) -> float:
    remed = weighted_progress(
        state.remediation_scores, state.risk_weights, state.ground_truth_vulns)
    ver_q = weighted_progress(
        {cid: d.get("version", 0.0) for cid, d in state.remediation_details.items()},
        state.risk_weights, state.ground_truth_vulns)
    return clamp(0.72 * remed + 0.28 * ver_q)


def constraint_health(state: EngineState) -> float:
    budget = clamp(
        state.budget_points / max(1, state.initial_budget_points or 1))
    sla = 1.0 if state.initial_sla_clock <= 0 else clamp(
        state.sla_clock / max(1, state.initial_sla_clock))
    return clamp(0.55 * budget + 0.45 * sla)


def unresolved_counts(state: EngineState) -> tuple[int, int]:
    critical, high = 0, 0
    for cid, ev in state.ground_truth_evidence.items():
        if cid in state.remediated_vulns:
            continue
        if ev.severity == "CRITICAL":
            critical += 1
        elif ev.severity == "HIGH":
            high += 1
    return critical, high


def task_completion_score(state: EngineState, task_id: int) -> float:
    ident = identification_progress(state)
    remed = remediation_progress(state)
    fp_pen = min(0.28, 0.08 * len(state.false_positives))
    weak_pen = min(0.12, 0.03 * state.weak_findings)
    inv_pen = min(0.18, 0.04 * state.invalid_remediations)

    if task_id == 1:
        return clamp(0.72 * ident + 0.28 * state.risk_ranking_score
                     - fp_pen - weak_pen)
    if task_id == 2:
        return clamp(0.3 * ident + 0.7 * remed - fp_pen - inv_pen)

    crit, high = unresolved_counts(state)
    score = (0.18 * ident + 0.57 * remed + 0.1 * state.risk_ranking_score
             + 0.15 * constraint_health(state) - fp_pen - inv_pen)
    if crit > 0:
        score *= 0.3
    elif high > 0:
        score *= 0.88
    return clamp(score)
