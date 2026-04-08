"""
API routes for OSV scanning, ecosystem adapters, and environment state.
"""
from __future__ import annotations

import io
import json
import tempfile
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, File, UploadFile, HTTPException
from pydantic import BaseModel

from data.osv_client import osv_client
from data.adapters import detect_and_parse, DepNode

router = APIRouter(prefix="/api/v1", tags=["vulnerability"])


class ScanRequest(BaseModel):
    name: str
    version: str = ""
    ecosystem: str = "PyPI"


class ScanResult(BaseModel):
    package: str
    version: str
    ecosystem: str
    vulnerabilities: List[Dict[str, Any]]
    total: int


class BatchScanRequest(BaseModel):
    packages: List[ScanRequest]


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


@router.post("/scan", response_model=ScanResult)
async def scan_package(req: ScanRequest):
    """Scan package for vulnerabilities via OSV.dev."""
    vulns = osv_client.query_package(req.name, req.version, req.ecosystem)
    return ScanResult(
        package=req.name, version=req.version, ecosystem=req.ecosystem,
        vulnerabilities=vulns, total=len(vulns)
    )


@router.post("/scan/batch", response_model=List[ScanResult])
async def scan_batch(req: BatchScanRequest):
    """Batch scan packages."""
    results = []
    for pkg in req.packages[:50]:
        vulns = osv_client.query_package(pkg.name, pkg.version, pkg.ecosystem)
        results.append(ScanResult(
            package=pkg.name, version=pkg.version, ecosystem=pkg.ecosystem,
            vulnerabilities=vulns, total=len(vulns)
        ))
    return results


@router.post("/scan/lockfile", response_model=DepGraphResponse)
async def scan_lockfile(file: UploadFile = File(...)):
    """Parse lockfile and scan dependencies."""
    content = await file.read()
    fname = file.filename or "requirements.txt"
    suffix = "." + fname.rsplit(".", 1)[-1] if "." in fname else ".txt"

    with tempfile.NamedTemporaryFile(mode="wb", suffix=suffix, delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        eco, deps = detect_and_parse(tmp_path)
    except ValueError as e:
        raise HTTPException(400, str(e))

    nodes: List[DepGraphNode] = []
    total_vulns = 0
    for dep in deps[:60]:
        vulns = osv_client.query_package(dep.name, dep.version, dep.ecosystem)
        total_vulns += len(vulns)
        nodes.append(DepGraphNode(
            name=dep.name, version=dep.version, ecosystem=dep.ecosystem,
            direct=dep.direct, dependencies=dep.dependencies, cves=vulns
        ))

    return DepGraphResponse(
        ecosystem=eco, nodes=nodes,
        total_packages=len(nodes), total_vulnerabilities=total_vulns
    )


@router.get("/vuln/{vuln_id}")
async def get_vulnerability(vuln_id: str):
    """Fetch vulnerability details."""
    result = osv_client.query_vuln(vuln_id)
    if not result: raise HTTPException(404, f"Vulnerability {vuln_id} not found")
    return result


@router.get("/ecosystems")
async def list_ecosystems():
    """List supported ecosystems."""
    return {
        "ecosystems": [
            {"id": "PyPI", "lockfile": "requirements.txt", "description": "Python"},
            {"id": "npm", "lockfile": "package-lock.json", "description": "Node.js"},
            {"id": "Go", "lockfile": "go.sum", "description": "Go"},
            {"id": "CycloneDX", "lockfile": "bom.json", "description": "SBOM"},
        ]
    }
