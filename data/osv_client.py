"""
OSV.dev API client for Google's Open Source Vulnerabilities database.
"""
from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional

import urllib.request
import urllib.error

CACHE_DIR = os.path.join(os.path.dirname(__file__), "cve_cache")
OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_VULNS = "https://api.osv.dev/v1/vulns"
_REQ_TIMEOUT = 8


def _post_json(url: str, body: dict) -> Optional[dict]:
    try:
        req = urllib.request.Request(
            url, data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(req, timeout=_REQ_TIMEOUT) as resp:
            return json.loads(resp.read())
    except Exception: return None


def _get_json(url: str) -> Optional[dict]:
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=_REQ_TIMEOUT) as resp:
            return json.loads(resp.read())
    except Exception: return None


def _parse_cvss_vector(vec: str) -> float:
    """Extract numeric score from CVSS vector."""
    score, vec_upper = 5.0, vec.upper()
    if "AV:N" in vec_upper: score += 1.5
    if "AC:L" in vec_upper: score += 1.0
    if "C:H" in vec_upper or "I:H" in vec_upper or "A:H" in vec_upper: score += 1.5
    if "PR:N" in vec_upper: score += 0.5
    return min(10.0, round(score, 1))


def _cvss_from_severity(sev_list: list) -> float:
    for s in sev_list:
        if "score" in s:
            val = s["score"]
            if isinstance(val, (int, float)): return float(val)
            val_str = str(val).strip()
            if val_str.startswith("CVSS:"): return _parse_cvss_vector(val_str)
            try: return float(val_str)
            except (ValueError, TypeError): pass
        if s.get("type") == "CVSS_V3" and "score" in s:
            return _parse_cvss_vector(str(s["score"]))
    return 5.0


def _severity_label(cvss: float) -> str:
    if cvss >= 9.0: return "CRITICAL"
    if cvss >= 7.0: return "HIGH"
    if cvss >= 4.0: return "MEDIUM"
    return "LOW" if cvss >= 0.1 else "NONE"


def _extract_fixed(vuln: dict, pkg_name: str) -> Optional[str]:
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("name", "").lower() == pkg_name.lower():
            for r in affected.get("ranges", []):
                for ev in r.get("events", []):
                    if "fixed" in ev: return ev["fixed"]
    return None


class OSVClient:
    """OSV.dev client with disk-level caching."""

    def __init__(self):
        os.makedirs(CACHE_DIR, exist_ok=True)

    def _cache_path(self, ecosystem: str, pkg: str) -> str:
        safe = f"{ecosystem}__{pkg}".replace("/", "_").replace("\\", "_")
        return os.path.join(CACHE_DIR, f"{safe}.json")

    def query_package(self, name: str, version: str, ecosystem: str = "PyPI") -> List[Dict[str, Any]]:
        cp = self._cache_path(ecosystem, name)
        if os.path.exists(cp) and (time.time() - os.path.getmtime(cp)) < 86400:
            with open(cp) as f: return json.load(f)

        body = {"package": {"name": name, "ecosystem": ecosystem}}
        if version: body["version"] = version

        resp = _post_json(OSV_QUERY, body)
        vulns_raw = (resp or {}).get("vulns", [])

        results = []
        for v in vulns_raw[:20]:
            aliases = v.get("aliases", [])
            cve_id = next((a for a in aliases if a.startswith("CVE-")), v.get("id", ""))
            sev = v.get("severity", v.get("database_specific", {}).get("severity", []))
            if isinstance(sev, str):
                cvss = {"CRITICAL": 9.5, "HIGH": 8.0, "MODERATE": 6.0, "LOW": 3.0}.get(sev.upper(), 5.0)
            elif isinstance(sev, list):
                cvss = _cvss_from_severity(sev)
            else:
                cvss = 5.0

            results.append({
                "cve_id": cve_id or v.get("id", "UNKNOWN"),
                "osv_id": v.get("id", ""),
                "summary": (v.get("summary") or v.get("details", ""))[:200],
                "cvss_score": round(cvss, 1), "severity": _severity_label(cvss),
                "fixed_version": _extract_fixed(v, name), "published": v.get("published", ""),
                "ecosystem": ecosystem, "package": name,
            })

        # Fixture fallback for offline usage
        if not results:
            from data.fixtures import get_mock_vulns
            results = get_mock_vulns(name, version, ecosystem)

        try:
            with open(cp, "w") as f: json.dump(results, f, indent=2)
        except OSError: pass
        return results

    def query_vuln(self, vuln_id: str) -> Optional[Dict[str, Any]]:
        return _get_json(f"{OSV_VULNS}/{vuln_id}")


osv_client = OSVClient()

