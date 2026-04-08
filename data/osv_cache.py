from __future__ import annotations
import json, os, random
from typing import Any, Dict, List, Optional

CACHE = os.path.join(os.path.dirname(__file__), "osv_cache.json")

class OSVCache:
    """Local CVE metadata cache."""
    def __init__(self):
        self._cache: Dict[str, Dict[str, Any]] = {}
        if os.path.exists(CACHE):
            with open(CACHE, "r") as f: self._cache = json.load(f)
        else: self._gen()
        self._rank()

    def _gen(self):
        rng = random.Random(42)
        d = {}
        # Traps / Killers / Mixed populations
        for i in range(30): d[f"CVE-2024-T00{i:02d}"] = {"cvss_score": round(rng.uniform(8.5, 10.0), 1), "epss_score": round(rng.uniform(0.001, 0.05), 4), "severity": "CRITICAL", "kev_listed": False}
        for i in range(30): d[f"CVE-2024-K00{i:02d}"] = {"cvss_score": round(rng.uniform(5.0, 7.5), 1), "epss_score": round(rng.uniform(0.6, 0.95), 4), "severity": "MEDIUM", "kev_listed": rng.random() > 0.75}
        for i in range(200):
            c = round(rng.uniform(0.5, 9.8), 1)
            s = "NONE" if c < 1.5 else ("LOW" if c < 4.0 else ("MEDIUM" if c < 7.0 else ("HIGH" if c < 9.0 else "CRITICAL")))
            d[f"CVE-2024-S0{i:03d}"] = {"cvss_score": c, "epss_score": round(rng.uniform(0.005, min(0.9, c/10)), 4), "severity": s, "kev_listed": rng.random() > 0.92}
        self._cache = d
        with open(CACHE, "w") as f: json.dump(d, f, indent=2)

    def _rank(self):
        s = sorted(v["epss_score"] for v in self._cache.values())
        for v in self._cache.values(): v["epss_percentile"] = round(sum(1 for x in s if x <= v["epss_score"]) / len(s), 4)

    def get_cve_info(self, cid: str) -> Dict[str, Any]:
        return self._cache.get(cid, {"cvss_score": 5.0, "epss_score": 0.01, "epss_percentile": 0.5, "severity": "MEDIUM", "kev_listed": False})

    def sample_cves(self, n: int, t: str = "mixed", rng: Optional[random.Random] = None) -> List[str]:
        keys = [k for k in self._cache.keys() if (t=="traps" and "T00" in k) or (t=="killers" and "K00" in k) or (t=="mixed")]
        return (rng or random).sample(keys, min(n, len(keys)))

cache = OSVCache()
