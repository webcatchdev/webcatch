# Webcatch — Docker build
FROM python:3.11-slim-bookworm

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app

# Copy deps first for layer caching
COPY --chown=appuser:appuser requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app code
COPY --chown=appuser:appuser . .

# Data volume for SQLite DB
VOLUME ["/app/data"]

EXPOSE 9120

ENV PYTHONUNBUFFERED=1
ENV INSPECTOR_PORT=9120
ENV INSPECTOR_HOST=0.0.0.0
ENV WEBCATCH_ENV=production
ENV LOCAL_LLM_URL=http://host.docker.internal:8081/v1/chat/completions
ENV LOCAL_LLM_MODEL=qwen-local

USER appuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9120/api/health', timeout=5)" || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "9120"]
