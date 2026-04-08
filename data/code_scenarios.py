"""
Code scenario corpus backed by curated real-world dependency incidents.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import random

from examples.catalog import CURATED_EXAMPLES


@dataclass(frozen=True)
class CodeScenario:
    idx: int
    path: str
    code: str
    language: str
    ecosystem: str
    package: str
    severity: str
    cvss_score: float
    fixed_version: str
    summary: str
    present_vulns: Tuple[str, ...]
    decoy_imports: Tuple[str, ...]
    difficulty: float
    vuln_lines: Tuple[int, ...]
    fix_hint: str
    context: str
    incident_source: str


def _fix_hint(package: str, fixed_version: str, summary: str) -> str:
    return f"Upgrade {package}>={fixed_version}; {summary}"


def build_corpus(rng: Optional[random.Random] = None) -> List[CodeScenario]:
    del rng
    scenarios: List[CodeScenario] = []
    for example in CURATED_EXAMPLES:
        scenarios.append(
            CodeScenario(
                idx=example.idx,
                path=example.path,
                code=example.code,
                language=example.language,
                ecosystem=example.ecosystem,
                package=example.package,
                severity=example.severity,
                cvss_score=float(example.cvss_score),
                fixed_version=example.fixed_version,
                summary=example.summary,
                present_vulns=(example.cve_id,),
                decoy_imports=(),
                difficulty=example.difficulty,
                vuln_lines=example.vuln_lines,
                fix_hint=_fix_hint(example.package, example.fixed_version, example.summary),
                context=f"{example.title}. {example.context}",
                incident_source=example.incident_source,
            )
        )
    return scenarios


def build_composite(
    base: List[CodeScenario],
    n_files: int = 3,
    rng: Optional[random.Random] = None,
) -> Dict[str, Any]:
    chooser = rng or random.Random(31415)
    shuffled = list(base)
    chooser.shuffle(shuffled)
    picks: List[CodeScenario] = []
    seen_cves = set()
    for scenario in shuffled:
        cve_id = scenario.present_vulns[0]
        if cve_id in seen_cves:
            continue
        picks.append(scenario)
        seen_cves.add(cve_id)
        if len(picks) >= min(n_files, len(base)):
            break
    if len(picks) < min(n_files, len(base)):
        for scenario in shuffled:
            if scenario in picks:
                continue
            picks.append(scenario)
            if len(picks) >= min(n_files, len(base)):
                break

    files: Dict[str, str] = {}
    all_vulns: List[str] = []
    total_diff = 0.0
    selected: List[Tuple[str, CodeScenario]] = []
    seen_paths = set()

    for i, scenario in enumerate(picks):
        file_name = scenario.path
        if file_name in seen_paths:
            stem, dot, suffix = file_name.rpartition(".")
            if dot:
                file_name = f"{stem}_{i}.{suffix}"
            else:
                file_name = f"{file_name}_{i}"
        seen_paths.add(file_name)
        files[file_name] = scenario.code
        all_vulns.extend(scenario.present_vulns)
        total_diff += scenario.difficulty
        selected.append((file_name, scenario))

    return {
        "files": files,
        "vulns": list(dict.fromkeys(all_vulns)),
        "difficulty": round(total_diff / max(1, len(picks)), 2),
        "n_files": len(picks),
        "scenarios": selected,
    }


CORPUS = build_corpus()
CORPUS_BY_DIFFICULTY = sorted(CORPUS, key=lambda scenario: scenario.difficulty)
