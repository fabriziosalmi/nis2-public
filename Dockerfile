FROM python:3.11-slim

# Install system dependencies (Nmap and WeasyPrint dependencies)
RUN apt-get update && apt-get install -y \
    nmap \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libcairo2 \
    libffi-dev \
    libjpeg-dev \
    libopenjp2-7-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create a non-root user for security
RUN useradd -m nis2user && chown -R nis2user:nis2user /app
USER nis2user

# Default command
ENTRYPOINT ["python", "-m", "nis2_checker.main"]
CMD ["--help"]
