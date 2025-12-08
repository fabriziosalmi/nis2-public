# Use official Python image (already has everything we need)
FROM python:3.11-slim

WORKDIR /app

# Install Python dependencies only (no apt packages to avoid hash issues)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY nis2scan/ ./nis2scan/
COPY templates/ ./templates/

# Copy default config
COPY config.example.yaml ./config.yaml

# Create directories
RUN mkdir -p reports evidence

# Default command
CMD ["python", "-m", "nis2scan.cli", "serve", "--port", "8000"]
