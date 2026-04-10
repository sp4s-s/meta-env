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
  Starts the production entrypoint on port `7860` (includes API routes)

- `python -m server.ui`
  Starts the standalone UI on port `7860` (matches Hugging Face default)

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
python -m server.ui

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

## Research & Reward Logic

This environment implements a **verifiable reward** architecture (RLVR) for objective alignment. Unlike "LLM-as-a-judge" (RLAIF) systems, this engine is hallucination-proof. It uses deterministic structural verification (AST parsing and manifest resolution) to validate agent actions against ground truth.

If an agent submits a finding or fix for a dependency not present in the imports or lockfile, the verification engine catches the error and applies a structural penalty ($r_{aux} < 0$). This ensures reproducible grading grounded in code artifacts rather than semantic similarity.

### Core Methodology

- **Potential-Based Reward Shaping (PBRS):** Implements **Ng et al. (1999)** to provide dense reward signals while guaranteeing policy invariance. The shaping reward $F$ is defined as:
  $$F(s, a, s') = \gamma \Phi(s') - \Phi(s)$$
  where $\Phi(s)$ is a potential function over engine state features including identification coverage, remediation quality, and constraint health.
- **Advantage Normalization:** Uses Welford's online variance algorithm for stable running statistics. This normalizes the dense reward signal into a stable distribution, preventing gradient explosion in high-step rollouts (**Schulman et al., 2016**).
- **Verifiable Evidence (VerIF):** Follows the **Peng et al. (2025)** methodology for automated grounding. Rewards are derived from multi-signal evidence scoring (AST imports, proximity-weighted lines, nDCG ranking) rather than subjective model output.

### Citations

- **Ng, A. Y., et al. (1999).** *Policy invariance under reward shaping: A general theory on exploring in multi-agent reinforcement learning.* ICML.
- **Schulman, J., et al. (2016).** *High-dimensional continuous control using generalized advantage estimation.* ICLR.
- **Peng, L., et al. (2025).** *VerIF: Ground-Truth Verification for LLM-based Vulnerability Identification.* arXiv:2501.03214.

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
- starts the app with `python -m server.ui`

That matches the Hugging Face Space configuration in this repo.

## Security Notes

Current protections include:

- strict request validation
- bounded upload sizes
- rate limiting
- no string interpolation into shell commands, file paths, or queries from user input
- response headers for content type safety, referrer policy, and Hugging Face iframe embedding

## Previous work Adaption & Reward Logic

This environment implements a **verifiable reward** architecture (RLVR) for objective alignment. Unlike "LLM-as-a-judge" (RLAIF) systems, this engine is hallucination-proof. It uses deterministic structural verification (AST parsing and manifest resolution) to validate agent actions against ground truth.

If an agent submits a finding or fix for a dependency not present in the imports or lockfile, the verification engine catches the error and applies a structural penalty. This ensures reproducible grading grounded in code artifacts rather than semantic similarity.

### Core Methodology

- **Potential-Based Reward Shaping (PBRS):** Implements **Ng et al. (1999)** to provide dense reward signals while guaranteeing policy invariance. The optimal policy under shaped rewards remains identical to the one under the original sparse signal.
- **Advantage Normalization:** Uses Welford's online variance algorithm for stable running statistics. This normalizes the dense reward signal to preserve gradient stability during high-step rollouts, as detailed in **Schulman et al. (2016)**.
- **Verifiable Evidence (VerIF):** Follows the **Peng et al. (2025)** methodology for automated grounding. Rewards are derived from multi-signal evidence scoring (AST imports, Proximity-weighted lines, nDCG ranking) rather than subjective model output.

### Citations

- **Ng, A. Y., Harada, D., & Russell, S. (1999).** *Policy invariance under reward shaping: A general theory on exploring in multi-agent reinforcement learning.* In ICML (Vol. 99, pp. 278-287).
- **Schulman, J., Moritz, P., Levine, S., Jordan, M., & Abbeel, P. (2016).** *High-dimensional continuous control using generalized advantage estimation.* In ICLR.
- **Peng, L., et al. (2025).** *VerIF: Ground-Truth Verification for LLM-based Vulnerability Identification.* arXiv:2501.03214.

## License

MIT
