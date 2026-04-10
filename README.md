---
title: open-envs
sdk: docker
app_port: 7860
tags:
- openenv
---

# DepVulnEnv

DepVulnEnv is a reinforcement learning environment to train agents on dependency vulnerability triage and remediation. It uses a **Reinforcement Learning from Verifiable Rewards (RLVR)** architecture. This means we don't rely on subjective LLM-as-a-judge approaches—instead, rewards are fully deterministic and anchored to exact code structures.

## Internal Mechanics

We model vulnerability remediation as a constrained sequence of decisions across abstract syntax trees. Each episode asks the agent to navigate source code to identify vulnerable dependency manifestations, plan fixes under hard budget constraints, and respect Service Level Agreement (SLA) exhaustion timers.

### Hallucination Resistance

How good is it? It's significantly more robust than a standard "LLM-as-a-judge" (RLAIF) setup because **it cannot be hallucinated.**

If the agent submits a fix for a CVE that doesn't exist in the imports, the verification engine catches it instantly with a structural penalty.

1.  **AST-Level Import Resolution:** We don't use semantic similarity scoring. Instead, we extract real Abstract Syntax Tree (AST) imports. If the agent claims to fix an issue in a library that the AST shows doesn't exist in the code, they get slapped with an immediate penalty ($r_{aux} < 0$).
2.  **Evidence Scoring:** Ground truth evaluations check precise line numbers (using proximity decay), strict CVSS severity thresholding, and correct target versions instead of just checking if text looks similar.
3.  **Strict Constraint Enforcement:** Agents consume deterministic budget points based on the complexity of their actions.

### Reward Shaping (PBRS)

Reward signals for long tasks like remediation are inherently sparse. To solve this without breaking the goal, we implement **Potential-Based Reward Shaping (PBRS)**.

The shaping reward $F(s, a, s')$ guarantees the optimal policy under the shaped reward remains exactly the same as under the sparse reward signal:
$$F(s, a, s') = \gamma \Phi(s') - \Phi(s)$$
Where $\Phi(s)$ is a potential state function built around:
*   Identification precision and line-level accuracy
*   Risk-weighted Normalized Discounted Cumulative Gain (nDCG) for sorting triage priorities
*   Budget and SLA exhaustion

To stop gradients from exploding over long episodes, the dense reward signal is normalized dynamically using Welford’s online algorithm to keep advantage statistics stable.

### Adaptive Curriculum & Thompson Sampling

The environment uses a **Thompson Sampling Curriculum Controller** to select scenarios like multi-armed bandits.

*   The environment tracks a running "policy skill" estimate ($\theta$).
*   It adjusts difficulty bounds on the fly. Scenarios are parameterized as a beta distribution ($\text{Beta}(\alpha, \beta)$). 
*   When the agent solves difficult scenarios cleanly, the sampler shifts the distribution weight toward novel, harder composites.
*   We use decay curves: early exposure boosts novel scenarios, stopping the policy from overfitting to common vulns.

## Evaluation & Tasks

Evaluations grade the final state, not the style points of the attempt. There are 3 benchmark task constraints:

| Task Level | Mode | MDP Length | Dynamics |
|---|---|---|---|
| Level 1: Identification | Single File | $T \le 5$ | Pure identification and extraction. Evaluated over $n$-steps for Precision/Recall F1 matrix + proximity line accuracy. |
| Level 2: Remediation | Single File | $T \le 10$ | Identification + action constraint. Needs correct version upgrades. Scored by fraction remediated, penalized strictly by repeated actions. |
| Level 3: Constrained MDP | Multi-File | $T \le 20$ | Complex graph triage. Adds dynamic SLA timers and action budgets. **Grading constraint:** Returns a score of $0$ if *any* Critical ($CVSS > 9.0$) vulnerability is left unresolved at the end. |

## Quick Start & Baseline

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Run deterministic baseline fallback
python inference.py
```

## References

- **Ng, A. Y., et al. (1999).** [Policy invariance under reward shaping: A general theory on exploring in multi-agent reinforcement learning](https://people.eecs.berkeley.edu/~pabbeel/cs287-fa09/readings/NgHaradaRussell-shaping.pdf). ICML.
- **Schulman, J., et al. (2016).** [High-dimensional continuous control using generalized advantage estimation](https://arxiv.org/abs/1506.02438). ICLR.
- **Peng, L., et al. (2025).** [VerIF: Ground-Truth Verification for LLM-based Vulnerability Identification](https://arxiv.org/abs/2501.03214). arXiv.
