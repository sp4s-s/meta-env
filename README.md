---
title: open-envs
sdk: docker
app_port: 7860
tags:
- openenv
---

# DepVulnEnv

OpenEnv benchmark for dependency vulnerability triage and remediation from source code.

## Overview

Agents receive source code blocks containing vulnerable dependency imports and must:
1. Identify which CVEs are present by analyzing import patterns and API usage
2. Propose correct remediations (upgrade versions, replacements, mitigations)
3. Manage budget and SLA constraints in multi-file scenarios

Supports Python (PyPI), Node.js (npm), and Go ecosystems.

## Tasks

| Task | Difficulty | Objective |
|------|-----------|-----------|
| 1 — Identify | Easy | Find CVEs in code, rank by risk |
| 2 — Remediate | Medium | Identify + fix under budget |
| 3 — Constrained | Hard | Multi-file remediation, budget + SLA |

## Action Space

```text
action_type: "identify" | "remediate" | "rank" | "done"
findings:    [{cve_id, file_path, line_number, package, severity, explanation}]
remediation: {cve_id, file_path, action, target_version, code_fix?, justification}
risk_ranking: [cve_id, ...]
```

## Setup

```bash
pip install -e "."
python inference.py
```

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `API_BASE_URL` | `https://litellm.sclr.ac/v1` | LLM endpoint |
| `MODEL_NAME` | `Qwen/Qwen2.5-72B-Instruct` | Model identifier |
| `HF_TOKEN` | — | Auth token for LLM calls |

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/scan` | Scan single package |
| POST | `/api/v1/scan/batch` | Batch scan (≤50 packages) |
| POST | `/api/v1/scan/lockfile` | Parse + scan lockfile |
| GET | `/api/v1/vuln/{id}` | Vulnerability details |
| GET | `/api/v1/ecosystems` | Supported ecosystems |

All endpoints enforce input validation, rate limiting (120 req/min per IP), and payload size bounds.

## Architecture

```text
api/        — FastAPI endpoints with input validation and rate limiting
curriculum/ — Thompson Sampling adaptive scenario selection
data/       — OSV client, ecosystem adapters, scenario generators
env/        — OpenEnv environment, models, reward shaping, verification
examples/   — Curated real-CVE source samples for rollout corpus
graders/    — Canonical task grading functions
server/     — Gradio UI, security middleware, app entrypoint
tasks/      — Task handler implementations
tests/      — Substrate and fixture tests
```

## Security

- Strict Pydantic schemas with regex allowlists on all user inputs
- Per-IP rate limiting on all API endpoints
- Path traversal prevention on file uploads
- No string interpolation of user input into queries, file paths, or shell commands
- Security headers: X-Content-Type-Options, X-Frame-Options, Referrer-Policy
- Request body size limits (5 MB global, 2 MB lockfiles)

## Research Credits

| Paper | Adaptation |
|-------|------------|
| Ng, Harada & Russell, "Policy Invariance Under Reward Transformations" (ICML 1999) | Potential-based reward shaping: F(s,s') = γΦ(s') − Φ(s) preserves optimal policies while providing dense training signal |
| Lightman et al., "Let's Verify Step by Step" (ICLR 2024) | Process-supervised verification: stepwise scoring of identification and remediation quality rather than outcome-only evaluation |
| Peng et al., "VerIF: Verification-guided Instruction Following" (2025) | Deterministic structural evidence checks (file, line, package, version) for auditable grading |
| Schulman et al., "High-Dimensional Continuous Control Using GAE" (ICLR 2016) | Running advantage normalization for stable reward distributions across episodes |
| Chen et al., "Teaching Large Language Models to Self-Debug" (ACL 2024) | Verification pressure via explicit error feedback in observation space |

## License

MIT
