# Usage

## Setup
```bash
conda activate sclr
pip install -e .
```

## Inference
```bash
export API_KEY="your-key"
export API_BASE_URL="https://router.huggingface.co/v1"
export MODEL_NAME="Qwen/Qwen2.5-72B-Instruct"
python inference.py
```

### Output Format
Follows the `[START]/[STEP]/[END]` protocol per Problem Statement:
```text
[START] task=cve_triage env=dep-vuln-env model=Qwen/Qwen2.5-72B-Instruct
[STEP] step=1 action={...} reward=-0.01 done=false error=null
[END] success=true steps=5 score=0.98 rewards=...
```

## API Validation (cURL)

**Scan a known-vulnerable PyPI package:**
```bash
curl -s -X POST http://localhost:7860/api/v1/scan \
     -H "Content-Type: application/json" \
     -d '{"name": "jinja2", "version": "3.1.3", "ecosystem": "PyPI"}'
# Expected: CVE-2024-56326 (CRITICAL, sandbox escape)
```

**Scan a known-vulnerable npm package:**
```bash
curl -s -X POST http://localhost:7860/api/v1/scan \
     -H "Content-Type: application/json" \
     -d '{"name": "elliptic", "version": "6.5.4", "ecosystem": "npm"}'
# Expected: CVE-2024-48949 (CRITICAL, signature bypass)
```

**Batch scan multiple packages:**
```bash
curl -s -X POST http://localhost:7860/api/v1/scan/batch \
     -H "Content-Type: application/json" \
     -d '{"packages": [
       {"name": "requests", "version": "2.31.0", "ecosystem": "PyPI"},
       {"name": "axios", "version": "1.6.7", "ecosystem": "npm"},
       {"name": "tornado", "version": "6.4", "ecosystem": "PyPI"},
       {"name": "ip", "version": "2.0.0", "ecosystem": "npm"}
     ]}'
# Expected: CVE-2024-35195, CVE-2024-39338, CVE-2024-32651, CVE-2024-29415
```

**Scan lockfile:**
```bash
curl -s -X POST http://localhost:7860/api/v1/scan/lockfile \
     -F "file=@data/seeds/pypi_seed.txt"
# Scans all 20 pinned PyPI packages for vulnerabilities
```

**List ecosystems:**
```bash
curl -s http://localhost:7860/api/v1/ecosystems
```

## Testing
```bash
conda run -n sclr python -m unittest discover -s tests -v
```

## Curated Examples
- Leave the Code Review input empty and click `Analyze code` to load a random high-risk incident from `examples/`.
- Rollout sampling now draws from the same curated `examples/` corpus, so training and manual review use the same scenario bank.

### Fixture Verification (42 packages, 15+ vuln classes)
```bash
conda run -n sclr python -m unittest tests.test_vuln_fixtures -v
```

## Fixture Packages

### PyPI (20 packages)
| Package | Version | CVE | Severity | Type |
|---------|---------|-----|----------|------|
| jinja2 | 3.1.3 | CVE-2024-56326 | CRITICAL | RCE |
| pillow | 10.2.0 | CVE-2024-28219 | CRITICAL | Overflow |
| tornado | 6.4 | CVE-2024-32651 | CRITICAL | SSTI |
| transformers | 4.38.0 | CVE-2024-3568 | CRITICAL | RCE |
| gradio | 4.19.0 | CVE-2024-47167 | CRITICAL | SSRF |
| setuptools | 69.0.0 | CVE-2024-6345 | HIGH | RCE |
| django | 5.0 | CVE-2024-27351 | HIGH | ReDoS |
| gunicorn | 21.2.0 | CVE-2024-1135 | HIGH | Smuggling |
| requests | 2.31.0 | CVE-2024-35195 | MEDIUM | Cert bypass |
| urllib3 | 2.1.0 | CVE-2024-37891 | MEDIUM | Info leak |

### npm (22 packages)
| Package | Version | CVE | Severity | Type |
|---------|---------|-----|----------|------|
| elliptic | 6.5.4 | CVE-2024-48949 | CRITICAL | Sig bypass |
| ip | 2.0.0 | CVE-2024-29415 | CRITICAL | SSRF |
| axios | 1.6.7 | CVE-2024-39338 | HIGH | SSRF |
| ws | 8.16.0 | CVE-2024-37890 | HIGH | DoS |
| cross-spawn | 7.0.3 | CVE-2024-21538 | HIGH | ReDoS |
| body-parser | 1.20.1 | CVE-2024-45590 | HIGH | DoS |
| express | 4.19.1 | CVE-2024-29041 | MEDIUM | Redirect |
| cookie | 0.6.0 | CVE-2024-47764 | MEDIUM | Bypass |

## Docker
```bash
docker build -t dep-vuln-env .
docker run -p 7860:7860 dep-vuln-env
```
