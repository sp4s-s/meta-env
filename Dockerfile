FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Pre-warm: generate synthetic fallback cache + pre-fetch CVEs for seed packages
RUN python -c "from data.osv_cache import cache; from data.generator import scenario_bank; print(f'Loaded {len(scenario_bank.scenarios)} scenarios')"

# Hugging Face Spaces standard port
EXPOSE 7860

CMD ["python", "-m", "server.ui"]

