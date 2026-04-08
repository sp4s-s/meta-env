---
title: open-envs
sdk: docker
app_port: 7860
tags:
- openenv
---

# DepVulnEnv

A research-grade OpenEnv benchmark for dependency vulnerability triage and remediation. Models real-world security engineering workflows: ranking prioritized risks and applying fixes under constraints.

## Task Overview
1. **`cve_triage`** (`easy`): Rank CVEs by composite priority. Graded via Kendall-tau.
2. **`fix_recommendation`** (`medium`): Resolve vulnerabilities using fix/suppress/accept actions.
3. **`constrained_remediation`** (`hard`): Resolve all criticals within budget and SLA limits.

## Environment Contract
- `reset(task_id)` -> `Observation`
- `step(action)` -> `Observation, Reward, done, info`
- `state()` -> `EngineState`
- `close()`

### Core Components
- **PBRS Reward Shaping**: Ng et al. (1999) policy-invariant shaping based on "Danger Mass" reduction.
- **Adaptive Curriculum**: Thompson Sampling + ZPD proximity bias (Oudeyer et al., 2007).
- **Vulnerability Modeling**: EPSS, KEV, SSVC, and VEX signals for realistic triage.

## Setup
```bash
pip install -r requirements.txt
python inference.py  # Run heuristic baseline
```

## Validation
```bash
python -m unittest discover -s tests
openenv validate
```
