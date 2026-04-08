---
title: open-envs
sdk: docker
app_port: 7860
tags:
- openenv
---

# DepVulnEnv v2.0

OpenEnv benchmark for dependency vulnerability triage and remediation. Supports Python (PyPI), Node.js (npm), and Go ecosystems.

## Features
- **OSV.dev Integration**: Live scanning via OSV API.
- **Ecosystem Adapters**: Native parsing for npm, pip, Go, and CycloneDX.
- **Offline Mode**: Deterministic fallback cache.
- **Multi-Objective**: Proritization, budget management, and SLA constraints.

## Tasks
| Task | Difficulty | Description |
|------|-----------|-------------|
| 1 — Triage | Easy | Rank CVEs by priority (CVSS, EPSS, KEV, SSVC, depth). |
| 2 — Fix | Medium | Apply remediation actions under budget. |
| 3 — Remediate | Hard | Clear critical risk under strict budget + SLA. |

## Action Space
```text
action_type: "rank" | "fix" | "suppress" | "accept" | "done"
cve_rankings: List[str]     # rank
cve_id: str               # target
target_node: str          # package
target_version: str       # fix
justification: str        # reason
```

## Setup
```bash
conda activate sclr
pip install -e "."
python inference.py
```

## Environment Variables
- `API_BASE_URL` default: `https://litellm.sclr.ac/v1`
- `MODEL_NAME` default: `Qwen/Qwen2.5-72B-Instruct`
- `HF_TOKEN` required for authenticated LLM calls
- `LOCAL_IMAGE_NAME` optional, only if using a Docker-image-based runner

## Baseline Scores
- Heuristic baseline runs successfully across all 3 tasks via `python inference.py`
- Latest local run: Task 1 `0.83`, Task 2 `0.99`, Task 3 `0.01`

## API
- `POST /api/v1/scan`
- `POST /api/v1/scan/batch`
- `POST /api/v1/scan/lockfile`
- `GET /api/v1/vuln/{id}`
- `GET /api/v1/ecosystems`

## Architecture
```text
api/        — FastAPI endpoints
curriculum/ — Adaptive sampling
data/       — OSV client, adapters, generators
env/        — OpenEnv environment & models
graders/    — Task grading logic
server/     — Gradio UI & app server
tasks/      — Task definitions
```
