# DepVulnEnv Usage

## Prerequisites
- Python 3.10+
- `openenv-core` (optional for local dev)
- OpenAI-compatible API key (optional for heuristic baseline)

## Setup
```bash
pip install -r requirements.txt
# or
pip install -e .
```

## Running the Benchmark
The benchmark can be run in two modes:
1. **Heuristic Baseline** (No API key needed)
2. **LLM Evaluation** (Define standard env vars)

```bash
# Set your environment variables (optional)
export API_KEY="your-key"
export MODEL_NAME="your-model"

# Execute inference
python inference.py
```

### Expected Output
The script follows the [START]/[STEP]/[END] protocol:

```text
[START] task=cve_triage env=dep-vuln-env model=Qwen/Qwen2.5-72B-Instruct
[STEP] step=1 action={"action_type":"rank",...} reward=-0.01 done=false error=null
...
[END] success=true steps=5 score=0.980 rewards=-0.01,-0.01,-0.01,-0.01,0.99
```

## Local Testing
Comprehensive test suite ensures scenario determinism and grader consistency:
```bash
python -m unittest discover -s tests -v
```

## Docker Deployment
```bash
docker build -t dep-vuln-env .
docker run -p 7860:7860 dep-vuln-env
```
The container exposes the OpenEnv server on port 7860, ready for Hugging Face Spaces or custom evaluation harnesses.
