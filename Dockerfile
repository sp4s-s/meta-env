FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Generate the synthetic cache to avoid any runtime overhead/network calls
RUN python -c "from data.osv_cache import cache"

# Hugging face spaces standard port
EXPOSE 7860

CMD ["python", "-m", "server.app"]
