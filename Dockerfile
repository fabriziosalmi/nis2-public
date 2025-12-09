# Use official Playwright image (matches requirements.txt version)
# This includes Python, Playwright, and all browser dependencies on Ubuntu 22.04 (Jammy)
FROM mcr.microsoft.com/playwright/python:v1.49.0-jammy

WORKDIR /app

# Install Python dependencies
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
