"""
OSV.dev API client with disk caching, input sanitization,
and deterministic fixture fallback for offline evaluation.
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, List, Optional

import urllib.request
import urllib.error

CACHE_DIR = os.path.join(os.path.dirname(__file__), "cve_cache")
OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_VULNS = "https://api.osv.dev/v1/vulns"
_REQ_TIMEOUT = 8

_SAFE_PKG = re.compile(r"^[A-Za-z0-9_.@/\-]{1,200}$")
_SAFE_ECO = frozenset({"PyPI", "npm", "Go", "CycloneDX", "Maven"})


def _sanitize_pkg(name: str) -> str:
    if not _SAFE_PKG.match(name):
        raise ValueError(f"Invalid package name: {name!r}")
    return name


def _sanitize_eco(eco: str) -> str:
    if eco not in _SAFE_ECO:
        raise ValueError(f"Unsupported ecosystem: {eco!r}")
    return eco


def _post_json(url: str, body: dict) -> Optional[dict]:
    try:
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=_REQ_TIMEOUT) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def _get_json(url: str) -> Optional[dict]:
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=_REQ_TIMEOUT) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def _parse_cvss_vector(vec: str) -> float:
    score, v = 5.0, vec.upper()
    if "AV:N" in v:
        score += 1.5
    if "AC:L" in v:
        score += 1.0
    if any(f"{x}:H" in v for x in ("C", "I", "A")):
        score += 1.5
    if "PR:N" in v:
        score += 0.5
    return min(10.0, round(score, 1))


def _cvss_from_severity(sev_list: list) -> float:
    for s in sev_list:
        if "score" in s:
            val = s["score"]
            if isinstance(val, (int, float)):
                return float(val)
            val_str = str(val).strip()
            if val_str.startswith("CVSS:"):
                return _parse_cvss_vector(val_str)
            try:
                return float(val_str)
            except (ValueError, TypeError):
                pass
        if s.get("type") == "CVSS_V3" and "score" in s:
            return _parse_cvss_vector(str(s["score"]))
    return 5.0


def _severity_label(cvss: float) -> str:
    if cvss >= 9.0:
        return "CRITICAL"
    if cvss >= 7.0:
        return "HIGH"
    if cvss >= 4.0:
        return "MEDIUM"
    return "LOW" if cvss >= 0.1 else "NONE"


def _extract_fixed(vuln: dict, pkg_name: str) -> Optional[str]:
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("name", "").lower() == pkg_name.lower():
            for r in affected.get("ranges", []):
                for ev in r.get("events", []):
                    if "fixed" in ev:
                        return ev["fixed"]
    return None


class OSVClient:
    """OSV.dev client with per-package disk cache (24h TTL)."""

    def __init__(self) -> None:
        os.makedirs(CACHE_DIR, exist_ok=True)

    def _cache_path(self, ecosystem: str, pkg: str) -> str:
        # Sanitize for filesystem safety
        safe = re.sub(r"[^A-Za-z0-9_.\-]", "_", f"{ecosystem}__{pkg}")[:200]
        return os.path.join(CACHE_DIR, f"{safe}.json")

    def query_package(
        self, name: str, version: str, ecosystem: str = "PyPI",
    ) -> List[Dict[str, Any]]:
        name = _sanitize_pkg(name)
        ecosystem = _sanitize_eco(ecosystem)

        cp = self._cache_path(ecosystem, name)
        if os.path.exists(cp) and (time.time() - os.path.getmtime(cp)) < 86400:
            with open(cp) as f:
                return json.load(f)

        body: dict = {"package": {"name": name, "ecosystem": ecosystem}}
        if version:
            body["version"] = version

        resp = _post_json(OSV_QUERY, body)
        vulns_raw = (resp or {}).get("vulns", [])

        results: List[Dict[str, Any]] = []
        for v in vulns_raw[:20]:
            aliases = v.get("aliases", [])
            cve_id = next(
                (a for a in aliases if a.startswith("CVE-")), v.get("id", ""))
            sev = v.get("severity", v.get("database_specific", {}).get("severity", []))
            if isinstance(sev, str):
                cvss = {"CRITICAL": 9.5, "HIGH": 8.0, "MODERATE": 6.0,
                        "LOW": 3.0}.get(sev.upper(), 5.0)
            elif isinstance(sev, list):
                cvss = _cvss_from_severity(sev)
            else:
                cvss = 5.0

            results.append({
                "cve_id": cve_id or v.get("id", "UNKNOWN"),
                "osv_id": v.get("id", ""),
                "summary": (v.get("summary") or v.get("details", ""))[:200],
                "cvss_score": round(cvss, 1),
                "severity": _severity_label(cvss),
                "fixed_version": _extract_fixed(v, name),
                "published": v.get("published", ""),
                "ecosystem": ecosystem,
                "package": name,
            })

        if not results:
            from data.fixtures import get_mock_vulns
            results = get_mock_vulns(name, version, ecosystem)

        try:
            with open(cp, "w") as f:
                json.dump(results, f, indent=2)
        except OSError:
            pass
        return results

    def query_vuln(self, vuln_id: str) -> Optional[Dict[str, Any]]:
        if not re.match(r"^[A-Za-z0-9\-]{3,64}$", vuln_id):
            return None
        return _get_json(f"{OSV_VULNS}/{vuln_id}")


osv_client = OSVClient()
