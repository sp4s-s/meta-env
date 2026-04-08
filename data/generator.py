"""
Scenario generator — dependencies and CVEs from OSV.dev with fixture fallback.
"""
from __future__ import annotations

import os
import random
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import networkx as nx

from .adapters import DepNode, parse_npm_lockfile, parse_pip_requirements, parse_go_sum
from .osv_client import osv_client
from .osv_cache import cache as _synthetic_cache

SEEDS_DIR = os.path.join(os.path.dirname(__file__), "seeds")


@dataclass(frozen=True)
class ScenarioSeed:
    idx: int
    difficulty: float
    n_packages: int
    cve_density: float
    max_depth: int
    has_diamond_conflicts: bool
    trap_ratio: float
    killer_ratio: float
    ecosystem: str = "PyPI"


def _load_seed_deps() -> Dict[str, List[DepNode]]:
    """Load dependencies from bundled seed lockfiles."""
    out: Dict[str, List[DepNode]] = {}
    pypi = os.path.join(SEEDS_DIR, "pypi_seed.txt")
    npm = os.path.join(SEEDS_DIR, "npm_seed.json")
    gosum = os.path.join(SEEDS_DIR, "go_seed.sum")

    if os.path.exists(pypi): out["PyPI"] = parse_pip_requirements(pypi)
    if os.path.exists(npm): out["npm"] = parse_npm_lockfile(npm)
    if os.path.exists(gosum): out["Go"] = parse_go_sum(gosum)
    return out


_SEED_DEPS = _load_seed_deps()


def _query_cves(dep: DepNode) -> List[Dict[str, Any]]:
    """Query OSV for CVEs. Returns empty list on failure."""
    try:
        return osv_client.query_package(dep.name, dep.version, dep.ecosystem)
    except Exception:
        return []


class ScenarioGenerator:
    """Deterministic scenario generation from package metadata + OSV CVEs."""

    def __init__(self):
        self.scenarios = self._init_bank()
        self._vuln_cache: Dict[str, List[Dict[str, Any]]] = {}

    def _init_bank(self) -> List[ScenarioSeed]:
        rng = random.Random(314159)
        seeds: List[ScenarioSeed] = []
        ecosystems = ["PyPI", "npm", "Go"]
        for i in range(50):
            d = 0.1 if i < 10 else (0.4 if i < 30 else 0.8)
            eco = ecosystems[i % len(ecosystems)]
            seeds.append(ScenarioSeed(
                idx=i,
                difficulty=round(rng.uniform(d, d + 0.2), 2),
                n_packages=rng.randint(6 if i < 10 else 12, 14 if i < 10 else 35),
                cve_density=0.25 if i < 10 else 0.35,
                max_depth=2 if i < 10 else 5,
                has_diamond_conflicts=i >= 10,
                trap_ratio=0.0 if i < 10 else 0.3,
                killer_ratio=0.0 if i < 10 else 0.2,
                ecosystem=eco,
            ))
        return seeds

    def _get_deps_for_eco(self, eco: str, n: int, rng: random.Random) -> List[DepNode]:
        pool = _SEED_DEPS.get(eco, [])
        if not pool:
            return [DepNode(name=f"pkg-{i}", version="1.0.0", ecosystem=eco, direct=i < 3)
                    for i in range(n)]
        return rng.sample(pool, min(n, len(pool)))

    def _enrich_cves(self, node_name: str, node_version: str, eco: str) -> List[Dict[str, Any]]:
        """Fetch CVEs for a package. Falls back to synthetic cache if empty."""
        key = f"{eco}:{node_name}:{node_version}"
        if key in self._vuln_cache: return self._vuln_cache[key]

        real = _query_cves(DepNode(name=node_name, version=node_version, ecosystem=eco))
        if real:
            self._vuln_cache[key] = real
            return real

        self._vuln_cache[key] = []
        return []

    def generate_graph(self, seed: ScenarioSeed) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        rng = random.Random(42 + seed.idx)
        deps = self._get_deps_for_eco(seed.ecosystem, seed.n_packages, rng)

        g = nx.DiGraph()
        for dep in deps:
            g.add_node(dep.name, version=dep.version, ecosystem=dep.ecosystem)

        node_names = {d.name for d in deps}
        for dep in deps:
            for child in dep.dependencies:
                if child in node_names:
                    if not nx.has_path(g, dep.name, child) or dep.name == child: continue
                    g.add_edge(dep.name, child)

        node_list = list(g.nodes())
        for i, n in enumerate(node_list[1:], 1):
            if g.in_degree(n) == 0 and g.out_degree(n) == 0:
                parent = rng.choice(node_list[:i])
                if not nx.has_path(g, n, parent): g.add_edge(parent, n)

        if seed.has_diamond_conflicts and len(node_list) >= 4:
            a, b, c, d = node_list[:4]
            for u, v in [(a, b), (a, c), (b, d), (c, d)]:
                if not g.has_edge(u, v) and not nx.has_path(g, v, u): g.add_edge(u, v)

        roots = [n for n, deg in g.in_degree() if deg == 0] or [node_list[0]]
        depths: Dict[str, int] = {}
        for n in g.nodes():
            paths = [nx.shortest_path_length(g, r, n) for r in roots if nx.has_path(g, r, n)]
            depths[n] = min(paths) if paths else 0

        nodes, cves = [], []
        for n in g.nodes():
            ver, eco = g.nodes[n].get("version", "0.0.0"), g.nodes[n].get("ecosystem", seed.ecosystem)
            cids: List[str] = []

            if rng.random() < seed.cve_density:
                real_cves = self._enrich_cves(n, ver, eco)
                if real_cves:
                    picks = rng.sample(real_cves, min(rng.randint(1, 2), len(real_cves)))
                    for cv in picks:
                        cid = cv["cve_id"]; cids.append(cid)
                        epss = self._estimate_epss(cv["cvss_score"], rng)
                        cves.append({
                            "cve_id": cid, "target_node": n, "cvss_score": cv["cvss_score"],
                            "epss_score": epss, "epss_percentile": round(rng.uniform(0.3, 0.95), 4),
                            "severity": cv["severity"], "reachability_depth": depths.get(n, 0),
                            "kev_listed": cv["cvss_score"] >= 9.0 and rng.random() > 0.7,
                            "vex_status": self._vex(depths.get(n, 0), cv["severity"], rng),
                            "ssvc_decision": self._ssvc(cv["severity"], epss, depths.get(n, 0),
                                                        cv["cvss_score"] >= 9.0 and rng.random() > 0.7),
                            "fixed_version": cv.get("fixed_version") or f"{ver.rsplit('.', 1)[0]}.999",
                            "summary": cv.get("summary", ""), "ecosystem": eco, "package": n,
                        })
                else:
                    roll = rng.random()
                    ctype = "traps" if roll < seed.trap_ratio else (
                        "killers" if roll < seed.trap_ratio + seed.killer_ratio else "mixed")
                    cid = _synthetic_cache.sample_cves(1, ctype, rng=rng)[0]; cids.append(cid)
                    info = _synthetic_cache.get_cve_info(cid)
                    cves.append({
                        "cve_id": cid, "target_node": n, "cvss_score": info["cvss_score"],
                        "epss_score": info["epss_score"], "epss_percentile": info.get("epss_percentile", 0.5),
                        "severity": info["severity"], "reachability_depth": depths.get(n, 0),
                        "kev_listed": info.get("kev_listed", False),
                        "vex_status": self._vex(depths.get(n, 0), info["severity"], rng),
                        "ssvc_decision": self._ssvc(info["severity"], info["epss_score"],
                                                    depths.get(n, 0), info.get("kev_listed", False)),
                        "fixed_version": f"1.0.{rng.randint(6, 9)}",
                    })

            nodes.append({
                "name": n, "version": ver, "depth": depths.get(n, 0), "direct": depths.get(n, 0) <= 1,
                "dependencies": sorted(g.successors(n)), "cves": cids, "ecosystem": eco,
            })

        rng.shuffle(nodes); rng.shuffle(cves)
        return nodes, cves

    @staticmethod
    def _estimate_epss(cvss: float, rng: random.Random) -> float:
        """Rough EPSS estimate from CVSS."""
        base = min(0.9, cvss / 12.0)
        return round(rng.uniform(max(0.005, base - 0.15), min(0.95, base + 0.15)), 4)

    @staticmethod
    def _vex(depth: int, sev: str, rng: random.Random) -> str:
        if depth >= 3 and sev in ("LOW", "NONE") and rng.random() > 0.5: return "not_affected"
        return "affected"

    @staticmethod
    def _ssvc(sev: str, eps: float, dep: int, kev: bool) -> str:
        if kev or (sev == "CRITICAL" and dep <= 1): return "act"
        if eps >= 0.7 or (sev == "HIGH" and dep <= 2): return "attend"
        return "track*" if eps >= 0.25 else "track"


scenario_bank = ScenarioGenerator()
