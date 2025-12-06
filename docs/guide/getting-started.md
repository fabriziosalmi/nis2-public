# Getting Started

## Introduction
**NIS2 Checker** is a modular, automated system designed to verify NIS2 compliance (Basic Cyber Hygiene) for URLs and IPs. It helps organizations meet the strict requirements of the NIS2 Directive by automating technical checks and providing governance tracking.

## Features
- **Connectivity Checks**: Verifies target reachability.
- **SSL/TLS Compliance**: Checks for minimum TLS version, certificate validity, and expiry.
- **Security Headers**: Verifies presence of critical security headers (HSTS, X-Content-Type-Options, etc.).
- **Infrastructure Audit**: Checks for SSH password auth, deprecated TLS, and open management ports using Nmap.
- **Network Discovery**: Scans entire subnets (CIDR) with low-impact settings.
- **Governance Checklist**: Integrated manual checklist for NIS2 governance priorities.
- **Authentication Support**: Supports Basic Auth and Bearer Tokens via environment variables.
- **Reporting**: Console output and JSON reports.
- **CI/CD Integration**: Ready-to-use GitHub Actions and GitLab CI pipelines.

> [!IMPORTANT]
> **Running Nmap on GitHub Actions**
> Please note that running port scans (Nmap) from public GitHub runners is generally forbidden. You should use **Self-Hosted Runners** or connect via a VPN (like **Tailscale**) to scan your infrastructure legally and safely. The provided workflow is disabled by default to prevent accidental misuse.

## Installation

We recommend using **Docker** for the easiest setup, as it includes all system dependencies (like Nmap and Pango for PDF generation).

### 🐳 Option 1: Docker (Recommended)

**Prerequisites**: Docker and Docker Compose installed.

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/fabriziosalmi/nis2-checker.git
    cd nis2-checker
    ```

2.  **Start the Platform**:
    ```bash
    docker-compose up -d
    ```

3.  **Access the Dashboard**:
    Open `http://localhost:8000` in your browser.

### 🐍 Option 2: Python (Manual)

### Prerequisites
- Python 3.11+
- Nmap (must be installed on the system)
- Chrome/Chromium (for screenshots)

### Steps

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/fabriziosalmi/nis2-checker.git
    cd nis2-checker
    ```

2.  **Create a Virtual Environment**:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

4.  **Run the Web App**:
    ```bash
    python -m nis2_checker.web
    ```

## Quick Start
```bash
python -m nis2_checker.main --config config.yaml --targets targets.yaml
```
