# NIS2 Platform -- API server image
# For full-stack deployment use infra/docker/docker-compose.prod.yml
FROM python:3.14-slim

# System dependencies for WeasyPrint PDF generation
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libcairo2 \
    libffi-dev \
    libjpeg-dev \
    libopenjp2-7-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY packages/scanner/pyproject.toml packages/scanner/
COPY packages/api/pyproject.toml packages/api/
RUN pip install --no-cache-dir -e packages/scanner && \
    pip install --no-cache-dir -e packages/api

# Copy application code
COPY packages/scanner/ packages/scanner/
COPY packages/api/ packages/api/

# Non-root user
RUN useradd -m nis2user && chown -R nis2user:nis2user /app
USER nis2user

EXPOSE 8000

ENTRYPOINT ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
