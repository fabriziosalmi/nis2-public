FROM python:3.11-slim

# Install system dependencies (Nmap is required)
RUN apt-get update && apt-get install -y \
    nmap \
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
