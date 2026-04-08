"""
Ecosystem adapters — parse lock files into dependency graphs.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class DepNode:
    name: str
    version: str
    ecosystem: str
    direct: bool = False
    dependencies: List[str] = field(default_factory=list)


def parse_npm_lockfile(path: str) -> List[DepNode]:
    """Parse package-lock.json (v2/v3)."""
    with open(path) as f:
        lock = json.load(f)

    nodes: Dict[str, DepNode] = {}
    packages = lock.get("packages", {})

    if not packages:
        for name, info in lock.get("dependencies", {}).items():
            nodes[name] = DepNode(
                name=name,
                version=info.get("version", "0.0.0"),
                ecosystem="npm",
                direct=not info.get("dev", False),
                dependencies=list(info.get("requires", {}).keys()),
            )
        return list(nodes.values())

    for key, info in packages.items():
        if key == "": continue
        name = key.split("node_modules/")[-1]
        nodes[name] = DepNode(
            name=name,
            version=info.get("version", "0.0.0"),
            ecosystem="npm",
            direct=info.get("dev", False) is False and "/" not in key.replace("node_modules/", "", 1),
            dependencies=list(info.get("dependencies", {}).keys()),
        )
    return list(nodes.values())


_PIP_RE = re.compile(r"^([A-Za-z0-9_.\-]+)\s*([=<>!~]+)\s*(.+)$")


def parse_pip_requirements(path: str) -> List[DepNode]:
    """Parse requirements.txt or pip freeze output."""
    nodes: List[DepNode] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith(("#", "-")): continue
            m = _PIP_RE.match(line)
            if m:
                nodes.append(DepNode(name=m.group(1), version=m.group(3).strip(), ecosystem="PyPI", direct=True))
            else:
                pkg = line.split("[")[0].split(";")[0].strip()
                if pkg:
                    nodes.append(DepNode(name=pkg, version="*", ecosystem="PyPI", direct=True))
    return nodes


def parse_go_sum(path: str) -> List[DepNode]:
    """Parse go.sum."""
    nodes: Dict[str, DepNode] = {}
    with open(path) as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) < 2: continue
            mod, ver = parts[0], parts[1].split("/")[0].lstrip("v")
            if mod not in nodes:
                nodes[mod] = DepNode(name=mod, version=ver, ecosystem="Go", direct=True)
    return list(nodes.values())


def parse_cyclonedx(path: str) -> List[DepNode]:
    """Parse CycloneDX JSON SBOM."""
    with open(path) as f:
        bom = json.load(f)
    nodes: List[DepNode] = []
    eco_map = {"npm": "npm", "pypi": "PyPI", "golang": "Go", "maven": "Maven"}
    for comp in bom.get("components", []):
        purl, eco = comp.get("purl", "").lower(), "PyPI"
        for key, val in eco_map.items():
            if key in purl:
                eco = val; break
        nodes.append(DepNode(
            name=comp.get("name", "unknown"),
            version=comp.get("version", "0.0.0"),
            ecosystem=eco,
            direct=comp.get("scope", "") != "optional",
        ))
    return nodes


ADAPTERS = {
    "package-lock.json": ("npm", parse_npm_lockfile),
    "requirements.txt": ("PyPI", parse_pip_requirements),
    "go.sum": ("Go", parse_go_sum),
    "bom.json": ("CycloneDX", parse_cyclonedx),
    "sbom.json": ("CycloneDX", parse_cyclonedx),
}


def detect_and_parse(path: str) -> Tuple[str, List[DepNode]]:
    """Auto-detect lock file type and parse."""
    base = os.path.basename(path)

    # Exact matches
    for pattern, (eco, parser) in ADAPTERS.items():
        if base == pattern:
            return eco, parser(path)

    # Suffix / content heuristics
    if base.endswith(".sum"):
        return "Go", parse_go_sum(path)
    if base.endswith(".json"):
        # Try npm first (look for "packages" or "dependencies" keys)
        try:
            import json as _json
            with open(path) as f:
                data = _json.load(f)
            if "packages" in data or "dependencies" in data:
                return "npm", parse_npm_lockfile(path)
            if "components" in data:
                return "CycloneDX", parse_cyclonedx(path)
        except Exception:
            pass
    if base.endswith(".txt"):
        return "PyPI", parse_pip_requirements(path)

    raise ValueError(f"Unknown lock file format: {base}")
