# Getting Started

## Overview

The NIS2 Compliance Scanner is an automated tool designed to help organizations comply with the NIS2 Directive requirements. It performs comprehensive security scans and generates detailed reports with evidence collection.

## Prerequisites

Before you begin, ensure you have:

- **Docker** and **Docker Compose** installed
- **Python 3.11+** (for local development)
- Basic understanding of network security concepts

## Installation Options

### Option 1: Docker (Recommended)

The easiest way to get started is using Docker:

```bash
# Clone the repository
git clone https://github.com/fabriziosalmi/nis2-public.git
cd nis2-public

# Start the scanner
docker-compose up -d

# Run a scan
docker-compose exec scanner python -m nis2scan.cli scan
```

### Option 2: Local Installation

For development or customization:

```bash
# Clone the repository
git clone https://github.com/fabriziosalmi/nis2-public.git
cd nis2-public

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run a scan
python -m nis2scan.cli scan -c test_config.yaml
```

## Configuration

Create a configuration file (e.g., `my_config.yaml`):

```yaml
project_name: "My First Scan"
scan_timeout: 10
concurrency: 10

targets:
  domains:
    - "example.com"
    - "mycompany.com"

features:
  dns_checks: true
  whois_checks: true

compliance_profile: "standard_nis2"
```

## Running Your First Scan

### With Docker

```bash
# Use your config file
CONFIG_FILE=./my_config.yaml docker-compose up -d

# Run the scan
docker-compose exec scanner python -m nis2scan.cli scan

# View reports at http://localhost:8000
```

### Local Installation

```bash
python -m nis2scan.cli scan -c my_config.yaml
```

## Understanding the Output

After a scan completes, you'll find:

- **HTML Report**: Interactive web report with all findings
- **JSON Report**: Machine-readable format for integration
- **Markdown Report**: Human-readable text format
- **Evidence Bundle**: ZIP file with all collected evidence
- **Prometheus Metrics**: Metrics file for monitoring

## Next Steps

- [Quick Start Guide](/guide/quick-start) - Get up and running in 5 minutes
- [Configuration Guide](/guide/configuration) - Detailed configuration options
- [Docker Guide](/guide/docker) - Advanced Docker deployment
- [Examples](/examples/) - Real-world usage examples

## Getting Help

If you encounter issues:

1. Check the [Troubleshooting Guide](/guide/troubleshooting)
2. Review the [Configuration Reference](/reference/config-schema)
3. Open an issue on GitHub
