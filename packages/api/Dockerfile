FROM python:3.14-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy scanner package first (dependency)
COPY packages/scanner /app/packages/scanner
RUN pip install --no-cache-dir /app/packages/scanner

# Copy API package
COPY packages/api /app/packages/api
RUN pip install --no-cache-dir /app/packages/api

WORKDIR /app/packages/api

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
