# Getting Started

## Introduction
**NIS2 Checker** uses a plugin-based, asynchronous scanning architecture. The parallel scanning engine allows concurrent checking of multiple targets and checks using `httpx` and `asyncio`, while keeping the core logic modular and aligned with NIS2 Art. 21.

## Key Features
- **Plugin Architecture**: Modular scanners for Web, Infrastructure, and Compliance checks.
- **Async Scanning**: Parallel execution using `httpx` with HTTP/2 support.
- **Vulnerability Disclosure**: Active checks for `security.txt` (RFC 9116).
- **Governance Integration**: Links technical scans with administrative compliance items.
- **Connectivity Checks**: Verifies target reachability.
- **SSL/TLS Compliance**: Checks minimum TLS version, certificate validity, and expiry.
- **Security Headers**: Verifies presence of critical security headers (HSTS, X-Content-Type-Options, etc.).
- **Infrastructure Audit**: Checks for SSH password auth, deprecated TLS, and open management ports using Nmap.
- **Network Discovery**: Scans entire subnets (CIDR) with configurable timing settings.
- **Governance Checklist**: Integrated manual checklist for NIS2 governance priorities.
- **Authentication Support**: Supports Basic Auth and Bearer Tokens via environment variables.
- **Reporting**: Console, JSON, HTML, PDF, CSV, Markdown, and JUnit XML output formats.
- **CI/CD Integration**: GitHub Actions and GitLab CI pipeline configurations included.

> [!IMPORTANT]
> **Running Nmap on GitHub Actions**
> Running port scans (Nmap) from public GitHub runners is forbidden by GitHub's Acceptable Use Policy. Use **Self-Hosted Runners** or connect via a VPN (such as **Tailscale**) to scan your infrastructure safely. The provided workflow uses `workflow_dispatch` (manual trigger only) to prevent accidental misuse.

## Installation

We recommend using **Docker** for the easiest setup, as it includes all system dependencies (like Nmap and Pango for PDF generation).

### 🐳 Option 1: Docker (Recommended)

**Prerequisites**: Docker and Docker Compose installed.

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/fabriziosalmi/nis2-public.git
    cd nis2-public
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
- Chrome/Chromium (for screenshots via Playwright)

### Steps

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/fabriziosalmi/nis2-public.git
    cd nis2-public
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
