"""
API routes for OSV scanning, ecosystem adapters, and environment control.

All inputs are validated via strict Pydantic schemas with bounded lengths.
No user-supplied string is interpolated into queries, file paths, or
shell commands — the adapter layer handles filesystem access through
an allowlist of known parsers.
"""
from __future__ import annotations

import os
import re
import tempfile
import time
from collections import defaultdict
from typing import Any, Dict, List

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field, field_validator

from data.adapters import detect_and_parse, DepNode
from data.osv_client import osv_client

router = APIRouter(prefix="/api/v1", tags=["vulnerability"])

# ── Rate Limiter ────────────────────────────────────────────────────

_RATE_WINDOW = 60
_RATE_LIMIT = 120
_rate_ledger: Dict[str, list] = defaultdict(list)


def _check_rate(client_ip: str) -> None:
    now = time.monotonic()
    timestamps = _rate_ledger[client_ip]
    _rate_ledger[client_ip] = [t for t in timestamps if now - t < _RATE_WINDOW]
    if len(_rate_ledger[client_ip]) >= _RATE_LIMIT:
        raise HTTPException(429, "Rate limit exceeded")
    _rate_ledger[client_ip].append(now)


# ── Input Validators ───────────────────────────────────────────────

_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.@/\-]{1,128}$")
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9_.+\-*~^<>=!]{0,64}$")
_SAFE_ECOSYSTEM = frozenset({"PyPI", "npm", "Go", "CycloneDX", "Maven"})
_SAFE_VULN_ID = re.compile(r"^[A-Za-z0-9\-]{3,64}$")


class ScanRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    version: str = Field(default="", max_length=64)
    ecosystem: str = Field(default="PyPI", max_length=16)

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not _SAFE_NAME.match(v):
            raise ValueError("Invalid package name")
        return v

    @field_validator("version")
    @classmethod
    def validate_version(cls, v: str) -> str:
        if v and not _SAFE_VERSION.match(v):
            raise ValueError("Invalid version string")
        return v

    @field_validator("ecosystem")
    @classmethod
    def validate_ecosystem(cls, v: str) -> str:
        if v not in _SAFE_ECOSYSTEM:
            raise ValueError(f"Unsupported ecosystem: {v}")
        return v


class ScanResult(BaseModel):
    package: str
    version: str
    ecosystem: str
    vulnerabilities: List[Dict[str, Any]]
    total: int


class BatchScanRequest(BaseModel):
    packages: List[ScanRequest] = Field(..., max_length=50)


class DepGraphNode(BaseModel):
    name: str
    version: str
    ecosystem: str
    direct: bool
    dependencies: List[str]
    cves: List[Dict[str, Any]]


class DepGraphResponse(BaseModel):
    ecosystem: str
    nodes: List[DepGraphNode]
    total_packages: int
    total_vulnerabilities: int


# ── Endpoints ───────────────────────────────────────────────────────

@router.post("/scan", response_model=ScanResult)
async def scan_package(req: ScanRequest, request: Request) -> ScanResult:
    _check_rate(request.client.host if request.client else "unknown")
    vulns = osv_client.query_package(req.name, req.version, req.ecosystem)
    return ScanResult(
        package=req.name, version=req.version, ecosystem=req.ecosystem,
        vulnerabilities=vulns, total=len(vulns),
    )


@router.post("/scan/batch", response_model=List[ScanResult])
async def scan_batch(req: BatchScanRequest, request: Request) -> List[ScanResult]:
    _check_rate(request.client.host if request.client else "unknown")
    results: List[ScanResult] = []
    for pkg in req.packages:
        vulns = osv_client.query_package(pkg.name, pkg.version, pkg.ecosystem)
        results.append(ScanResult(
            package=pkg.name, version=pkg.version, ecosystem=pkg.ecosystem,
            vulnerabilities=vulns, total=len(vulns),
        ))
    return results


_MAX_LOCKFILE_BYTES = 2 * 1024 * 1024
_ALLOWED_SUFFIXES = frozenset({".txt", ".json", ".sum", ".lock", ".toml"})


@router.post("/scan/lockfile", response_model=DepGraphResponse)
async def scan_lockfile(
    file: UploadFile = File(...),
    request: Request = None,
) -> DepGraphResponse:
    if request and request.client:
        _check_rate(request.client.host)

    content = await file.read()
    if len(content) > _MAX_LOCKFILE_BYTES:
        raise HTTPException(413, "Lockfile exceeds 2 MB limit")

    fname = file.filename or "requirements.txt"
    # Strip path separators to prevent directory traversal
    fname = os.path.basename(fname).replace("..", "")
    suffix = "." + fname.rsplit(".", 1)[-1] if "." in fname else ".txt"
    if suffix not in _ALLOWED_SUFFIXES:
        raise HTTPException(
            400, f"Unsupported file extension: {suffix}")

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=suffix, delete=False,
        ) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        eco, deps = detect_and_parse(tmp_path)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)

    nodes: List[DepGraphNode] = []
    total_vulns = 0
    for dep in deps[:60]:
        vulns = osv_client.query_package(dep.name, dep.version, dep.ecosystem)
        total_vulns += len(vulns)
        nodes.append(DepGraphNode(
            name=dep.name, version=dep.version, ecosystem=dep.ecosystem,
            direct=dep.direct, dependencies=dep.dependencies, cves=vulns,
        ))

    return DepGraphResponse(
        ecosystem=eco, nodes=nodes,
        total_packages=len(nodes), total_vulnerabilities=total_vulns,
    )


@router.get("/vuln/{vuln_id}")
async def get_vulnerability(vuln_id: str, request: Request) -> dict:
    _check_rate(request.client.host if request.client else "unknown")
    if not _SAFE_VULN_ID.match(vuln_id):
        raise HTTPException(400, "Invalid vulnerability ID format")
    result = osv_client.query_vuln(vuln_id)
    if not result:
        raise HTTPException(404, f"Vulnerability {vuln_id} not found")
    return result


@router.get("/ecosystems")
async def list_ecosystems() -> dict:
    return {
        "ecosystems": [
            {"id": "PyPI", "lockfile": "requirements.txt", "description": "Python"},
            {"id": "npm", "lockfile": "package-lock.json", "description": "Node.js"},
            {"id": "Go", "lockfile": "go.sum", "description": "Go"},
            {"id": "CycloneDX", "lockfile": "bom.json", "description": "SBOM"},
        ],
    }
