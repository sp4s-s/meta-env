"""
Curated vulnerable package fixtures — 2024-2026 PyPI + npm.
Pinned versions with known CVEs for offline testing and mock fallback.
"""
from __future__ import annotations
from typing import Any, Dict, List

# Each: (name, version, ecosystem, cve_id, cvss, severity, fixed_version, vuln_class, summary)
_RAW: List[tuple] = [
    # ── PyPI: RCE / code execution ──
    ("jinja2", "3.1.3", "PyPI", "CVE-2024-56326", 9.8, "CRITICAL", "3.1.5", "rce", "Sandbox escape via template injection"),
    ("pillow", "10.2.0", "PyPI", "CVE-2024-28219", 9.1, "CRITICAL", "10.3.0", "overflow", "Buffer overflow in image decoder"),
    ("werkzeug", "3.0.1", "PyPI", "CVE-2024-49767", 7.5, "HIGH", "3.0.6", "resource_exhaustion", "Multipart request DoS"),
    ("cryptography", "42.0.0", "PyPI", "CVE-2024-26130", 7.5, "HIGH", "42.0.4", "null_deref", "PKCS12 NULL pointer dereference"),
    ("paramiko", "3.4.0", "PyPI", "CVE-2024-6981", 7.4, "HIGH", "3.4.1", "auth_bypass", "Race condition in channel request handling"),
    ("aiohttp", "3.9.1", "PyPI", "CVE-2024-23334", 7.5, "HIGH", "3.9.2", "path_traversal", "Directory traversal via follow_symlinks"),
    ("django", "5.0", "PyPI", "CVE-2024-27351", 7.5, "HIGH", "5.0.3", "redos", "Truncated unicode ReDoS in EmailValidator"),
    ("flask", "3.0.0", "PyPI", "CVE-2023-30861", 7.5, "HIGH", "3.0.1", "session_fixation", "Session cookie on every response"),
    ("urllib3", "2.1.0", "PyPI", "CVE-2024-37891", 4.4, "MEDIUM", "2.2.2", "info_leak", "Proxy-Authorization header leak on redirect"),
    ("setuptools", "69.0.0", "PyPI", "CVE-2024-6345", 8.8, "HIGH", "70.0.0", "rce", "Remote code execution via package_index download"),
    ("certifi", "2024.2.2", "PyPI", "CVE-2024-39689", 7.5, "HIGH", "2024.7.4", "cert_validation", "Revoked root certificate trust"),
    ("requests", "2.31.0", "PyPI", "CVE-2024-35195", 5.6, "MEDIUM", "2.32.0", "cert_bypass", "Cert verification disabled on session redirect"),
    ("tornado", "6.4", "PyPI", "CVE-2024-32651", 9.8, "CRITICAL", "6.4.1", "ssti", "Server-side template injection"),
    ("lxml", "5.1.0", "PyPI", "CVE-2024-39573", 6.1, "MEDIUM", "5.2.1", "xxe", "DTD entity expansion"),
    ("pyyaml", "6.0.1", "PyPI", "CVE-2024-20060", 7.8, "HIGH", "6.0.2", "deserialization", "Unsafe YAML load arbitrary code"),
    ("sqlalchemy", "2.0.25", "PyPI", "CVE-2024-36242", 5.9, "MEDIUM", "2.0.30", "sqli", "Literal column SQL injection"),
    ("gunicorn", "21.2.0", "PyPI", "CVE-2024-1135", 7.5, "HIGH", "22.0.0", "http_smuggling", "HTTP request smuggling via chunked TE"),
    ("idna", "3.6", "PyPI", "CVE-2024-3651", 7.5, "HIGH", "3.7", "redos", "Quadratic complexity in IDNA encoding"),
    ("transformers", "4.38.0", "PyPI", "CVE-2024-3568", 9.8, "CRITICAL", "4.38.2", "rce", "Deserialization RCE via safetensors bypass"),
    ("gradio", "4.19.0", "PyPI", "CVE-2024-47167", 9.1, "CRITICAL", "4.44.0", "ssrf", "SSRF via /upload endpoint"),

    # ── npm: prototype pollution / RCE / path traversals ──
    ("express", "4.19.1", "npm", "CVE-2024-29041", 6.1, "MEDIUM", "4.19.2", "open_redirect", "Open redirect via URL parsing"),
    ("axios", "1.6.7", "npm", "CVE-2024-39338", 7.5, "HIGH", "1.7.4", "ssrf", "Server-side request forgery via path traversal"),
    ("lodash", "4.17.20", "npm", "CVE-2021-23337", 7.2, "HIGH", "4.17.21", "rce", "Command injection via template"),
    ("tar", "6.2.0", "npm", "CVE-2024-28863", 6.5, "MEDIUM", "6.2.1", "redos", "Cross-spawn regular expression DoS"),
    ("ws", "8.16.0", "npm", "CVE-2024-37890", 7.5, "HIGH", "8.17.1", "dos", "WebSocket DoS via invalid headers"),
    ("braces", "3.0.2", "npm", "CVE-2024-4068", 7.5, "HIGH", "3.0.3", "redos", "Uncontrolled resource via regex backtrack"),
    ("json5", "2.2.2", "npm", "CVE-2022-46175", 8.8, "HIGH", "2.2.3", "prototype_pollution", "Prototype pollution via parse"),
    ("node-fetch", "3.3.1", "npm", "CVE-2024-22025", 6.5, "MEDIUM", "3.3.2", "redos", "ReDoS in content-type parsing"),
    ("send", "0.18.0", "npm", "CVE-2024-43799", 5.0, "MEDIUM", "0.19.0", "xss", "XSS via untrusted input in redirect"),
    ("cookie", "0.6.0", "npm", "CVE-2024-47764", 5.3, "MEDIUM", "0.7.0", "cookie_bypass", "Cookie attribute parse bypass"),
    ("body-parser", "1.20.1", "npm", "CVE-2024-45590", 7.5, "HIGH", "1.20.3", "dos", "Unbounded payload asymmetric DoS"),
    ("path-to-regexp", "6.2.1", "npm", "CVE-2024-45296", 7.5, "HIGH", "6.3.0", "redos", "Polynomial ReDoS on malicious paths"),
    ("micromatch", "4.0.5", "npm", "CVE-2024-4067", 5.3, "MEDIUM", "4.0.6", "redos", "ReDoS on crafted glob pattern"),
    ("elliptic", "6.5.4", "npm", "CVE-2024-48949", 9.1, "CRITICAL", "6.5.6", "sig_bypass", "Invalid ECDSA signature verification"),
    ("nanoid", "3.3.6", "npm", "CVE-2024-55565", 4.0, "MEDIUM", "3.3.8", "predictable_id", "Reduced entropy on non-secure env"),
    ("cross-spawn", "7.0.3", "npm", "CVE-2024-21538", 7.5, "HIGH", "7.0.5", "redos", "ReDoS via shell metachar injection"),
    ("undici", "6.6.0", "npm", "CVE-2024-24758", 3.9, "LOW", "6.6.1", "info_leak", "Proxy-Authorization header forwarded"),
    ("esbuild", "0.20.0", "npm", "CVE-2024-29018", 6.1, "MEDIUM", "0.20.1", "path_traversal", "Development server path traversal"),
    ("ip", "2.0.0", "npm", "CVE-2024-29415", 9.8, "CRITICAL", "2.0.1", "ssrf", "isPublic/isPrivate SSRF bypass"),
    ("follow-redirects", "1.15.5", "npm", "CVE-2024-28849", 6.5, "MEDIUM", "1.15.6", "info_leak", "Authorization header leak on redirect"),
    ("postcss", "8.4.31", "npm", "CVE-2023-44270", 5.3, "MEDIUM", "8.4.32", "injection", "Newline injection in CSS parsing"),
    ("semver", "7.5.4", "npm", "CVE-2022-25883", 7.5, "HIGH", "7.5.5", "redos", "ReDoS on long semver strings"),
]

# Vuln class distribution coverage
VULN_CLASSES = sorted(set(r[7] for r in _RAW))

def _build(r: tuple) -> Dict[str, Any]:
    return {
        "cve_id": r[3], "package": r[0], "version": r[1], "ecosystem": r[2],
        "cvss_score": r[4], "severity": r[5], "fixed_version": r[6],
        "vuln_class": r[7], "summary": r[8],
    }

FIXTURES: List[Dict[str, Any]] = [_build(r) for r in _RAW]
PYPI_FIXTURES = [f for f in FIXTURES if f["ecosystem"] == "PyPI"]
NPM_FIXTURES = [f for f in FIXTURES if f["ecosystem"] == "npm"]

def get_mock_vulns(name: str, version: str, ecosystem: str = "PyPI") -> List[Dict[str, Any]]:
    """Mock OSV response from fixtures. Used when input is None or offline."""
    return [
        {
            "cve_id": f["cve_id"], "osv_id": f["cve_id"], "summary": f["summary"],
            "cvss_score": f["cvss_score"], "severity": f["severity"],
            "fixed_version": f["fixed_version"], "published": "2024-01-01T00:00:00Z",
            "ecosystem": f["ecosystem"], "package": f["package"],
        }
        for f in FIXTURES
        if f["package"] == name and f["ecosystem"] == ecosystem
    ]
