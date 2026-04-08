from __future__ import annotations
import random
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple
import networkx as nx
from .osv_cache import cache

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

class ScenarioGenerator:
    """Deterministic DG generation with seeded vulnerability distribution."""
    def __init__(self):
        self.scenarios = self._init_bank()

    def _init_bank(self) -> List[ScenarioSeed]:
        rng = random.Random(314159)
        seeds: List[ScenarioSeed] = []
        for i in range(50):
            d = 0.1 if i < 10 else (0.4 if i < 30 else 0.8)
            seeds.append(ScenarioSeed(
                idx=i, difficulty=round(rng.uniform(d, d+0.2), 2),
                n_packages=rng.randint(8 if i < 10 else 18, 16 if i < 10 else 54),
                cve_density=0.18 if i < 10 else 0.28,
                max_depth=2 if i < 10 else 6,
                has_diamond_conflicts=i >= 10,
                trap_ratio=0.0 if i < 10 else 0.3,
                killer_ratio=0.0 if i < 10 else 0.2
            ))
        return seeds

    def generate_graph(self, seed: ScenarioSeed) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        rng = random.Random(42 + seed.idx)
        g = nx.DiGraph()
        for i in range(seed.n_packages):
            g.add_node(f"pkg-{i}", version=f"1.0.{rng.randint(0, 5)}")

        for i in range(1, seed.n_packages):
            for p in rng.sample(range(i), rng.randint(1, min(2, i))):
                if not nx.has_path(g, f"pkg-{i}", f"pkg-{p}"): g.add_edge(f"pkg-{p}", f"pkg-{i}")

        if seed.has_diamond_conflicts and seed.n_packages >= 4:
            g.add_edges_from([("pkg-0","pkg-1"), ("pkg-0","pkg-2"), ("pkg-1","pkg-3"), ("pkg-2","pkg-3")])

        roots = [n for n, d in g.in_degree() if d == 0] or ["pkg-0"]
        depths = {n: min([nx.shortest_path_length(g, r, n) for r in roots if nx.has_path(g, r, n)] or [0]) for n in g.nodes()}

        nodes, cves = [], []
        for n in g.nodes():
            cids = []
            if rng.random() < seed.cve_density:
                ctype = "mixed"
                if seed.trap_ratio > 0:
                    roll = rng.random()
                    ctype = "traps" if roll < seed.trap_ratio else ("killers" if roll < seed.trap_ratio + seed.killer_ratio else "mixed")
                
                cid = cache.sample_cves(1, ctype, rng=rng)[0]
                cids.append(cid)
                info = cache.get_cve_info(cid)
                cves.append({
                    "cve_id": cid, "target_node": n, "cvss_score": info["cvss_score"],
                    "epss_score": info["epss_score"], "epss_percentile": info.get("epss_percentile", 0.5),
                    "severity": info["severity"], "reachability_depth": depths[n],
                    "kev_listed": info.get("kev_listed", False),
                    "vex_status": "not_affected" if depths[n] >= 3 and info["severity"] in ("LOW","NONE") and rng.random() > 0.5 else "affected",
                    "ssvc_decision": self._ssvc(info["severity"], info["epss_score"], depths[n], info.get("kev_listed", False)),
                    "fixed_version": f"1.0.{rng.randint(6, 9)}"
                })
            nodes.append({"name": n, "version": g.nodes[n]["version"], "depth": depths[n], "direct": depths[n] <= 1, "dependencies": sorted(g.successors(n)), "cves": cids})

        rng.shuffle(nodes); rng.shuffle(cves)
        return nodes, cves

    @staticmethod
    def _ssvc(sev: str, eps: float, dep: int, kev: bool) -> str:
        if kev or (sev == "CRITICAL" and dep <= 1): return "act"
        if eps >= 0.7 or (sev == "HIGH" and dep <= 2): return "attend"
        return "track*" if eps >= 0.25 else "track"

scenario_bank = ScenarioGenerator()
