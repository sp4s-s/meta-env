---
title: open-envs
sdk: docker
app_port: 7860
tags:
- openenv
---

# DepVulnEnv

DepVulnEnv is an OpenEnv-compatible environment for dependency vulnerability work from source code.
Each episode gives the agent one or more source files and asks it to:

- identify vulnerable dependencies
- rank confirmed findings
- propose fixes in the harder tasks
- work within budget and SLA constraints when those constraints are enabled

The repository includes a web UI, a small API surface, a baseline inference script, and the task logic used to score runs.

## What Runs Here

- `python -m server.app`
  Starts the Hugging Face / production entrypoint on port `7860`
  Serves the UI at `/`
  Serves API routes under `/api/v1`

- `python -m server.ui`
  Starts the standalone UI on port `7861`
  Useful when you only want to work on the Gradio frontend

- `python inference.py`
  Runs the baseline evaluator across tasks 1, 2, and 3
  Uses an LLM if `HF_TOKEN` is set
  Falls back to a deterministic heuristic if `HF_TOKEN` is missing

## Quick Start

Use the requirements file if you want the full app, including Gradio:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m server.app
```

Open `http://localhost:7860`.

If you need editable installs for code changes:

```bash
pip install -e .
```

Note: `requirements.txt` includes `gradio`; `pyproject.toml` does not.

## Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `API_BASE_URL` | `https://litellm.sclr.ac/v1` | Base URL for LLM calls in `inference.py` |
| `MODEL_NAME` | `Qwen/Qwen2.5-72B-Instruct` | Model used by the baseline runner |
| `HF_TOKEN` | unset | API key for LLM-backed inference |

If `HF_TOKEN` is not set, the evaluator still runs by using the built-in heuristic baseline.

## Tasks

| Task | Name | Max steps | What the agent must do |
|---|---|---:|---|
| `1` | Find vulnerable dependencies | `5` | Identify and rank vulnerable dependency usage in a single-file scenario |
| `2` | Plan dependency fixes | `10` | Identify findings and propose remediation under a budget |
| `3` | Multi-file constrained fix planning | `20` | Work across multiple files with both budget and SLA pressure |

Constraint behavior comes from `env/environment.py`:

- Budget is enabled for tasks `2` and `3`
- SLA countdown is only enforced in task `3`

## UI Guide

The UI is meant to show the current run, not dump the whole internal state blindly.

### Run tab

- shows the current episode id, mode, scenario, and active workspace
- shows live run metrics such as completion, step reward, episode reward, findings, fixes, budget, and SLA when relevant
- shows code with highlighted lines from ground-truth evidence and the latest step
- lets you submit manual steps for:
  - confirming a finding
  - planning a fix
  - prioritizing findings
  - finishing the run

### State tab

- `Run Snapshot`
  Compact view of the current observation

- `Episode State`
  Compact view of the tracked environment state

- `Reference Labels`
  Ground-truth labels for the loaded scenario when the toggle is enabled

- `Step Log`
  One row per submitted action with the target, file, reward, issue, and note

### History tab

- keeps completed runs in memory for the current process
- shows mode, scenario, workspace, completion, episode reward, and outcome counts
- the sidebar summary shows:
  - runs logged
  - latest completion
  - best completion
  - recent average over the last 10 runs
- use `Clear history` if you want to reset the in-memory history panel without restarting the app

## API

All API routes are mounted under `/api/v1`.

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/scan` | Scan a single package |
| `POST` | `/scan/batch` | Scan up to 50 packages |
| `POST` | `/scan/lockfile` | Parse and scan a manifest or lockfile |
| `GET` | `/vuln/{id}` | Return details for a vulnerability id |
| `GET` | `/ecosystems` | List supported ecosystems |

Guardrails on the API:

- request rate limiting per IP
- strict input validation
- path sanitization on uploaded filenames
- payload size limits for requests and lockfiles

## Baseline Evaluator

`inference.py` is a simple runner for all three tasks.

Behavior:

- with `HF_TOKEN`
  Calls the configured model through the OpenAI-compatible client

- without `HF_TOKEN`
  Falls back to a deterministic heuristic that scans imports and submits basic actions

Typical usage:

```bash
python inference.py
```

The script prints structured logs for:

- task start
- each step
- final score and reward list

## Repository Layout

| Path | Purpose |
|---|---|
| `api/` | FastAPI routes for package and lockfile scanning |
| `curriculum/` | Scenario sampling logic |
| `data/` | OSV cache, ecosystem adapters, fixtures, and scenario generation |
| `env/` | Environment state, reward shaping, verification, and observation building |
| `examples/` | Curated code samples used by the UI code review tab |
| `graders/` | Grading helpers |
| `server/` | App entrypoint and Gradio UI |
| `tasks/` | Task handlers for tasks 1, 2, and 3 |
| `tests/` | Automated tests |

## Deployment Notes

The Docker image:

- installs dependencies from `requirements.txt`
- pre-warms the cached scenario bank during build
- exposes port `7860`
- starts the app with `python -m server.app`

That matches the Hugging Face Space configuration in this repo.

## Security Notes

Current protections include:

- strict request validation
- bounded upload sizes
- rate limiting
- no string interpolation into shell commands, file paths, or queries from user input
- response headers for content type safety, referrer policy, and Hugging Face iframe embedding

## License

MIT
