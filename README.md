# NIS2 Compliance Checker

A modular, automated system to verify NIS2 compliance (Basic Cyber Hygiene) for URLs and IPs.

## Features

### 🛡️ Core Compliance
- **Connectivity Checks**: Verifies target reachability (IPv4/IPv6).
- **SSL/TLS Compliance**: Checks for minimum TLS version (1.2/1.3), certificate validity, and expiry.
- **Security Headers**: Verifies HSTS, X-Content-Type-Options, X-Frame-Options, CSP.

### 🧠 Strategic Intelligence (New in v0.4.0)
- **Strategic Compliance**:
    - **Incident Reporting (Art. 23)**: Interactive CLI helper for generating CSIRT-compliant early warning reports.
    - **EU/IT Specifics**: Validates `security.txt` (RFC 9116), Italian P.IVA/Privacy mandates, and Cookie Banner presence. 
    - **Resilience**: Detects WAF & CDN protection (Cloudflare, Akamai, AWS).
    - **Secrets Detection**: Scans for leaked AWS keys, private keys, and tokens.
    - **WHOIS Monitoring**: Alerts on domain expiry (< 30 days).
    - **Visual Evidence**: Captures automated screenshots of targets.
- **Holistic DNS Security**: Checks SPF, DMARC, and DNSSEC.
- **Reporting**: JSON, PDF, and HTML formats with compliance scoring.
- **Nmap Vulnerability Scan**: integration with `vulners` script to detect **CVEs** on open ports.
- **Service Hardening**: Detects SSH password auth, cleartext HTTP management ports, and insecure RDP/SMB.

### 📈 Persistence & Alerting
- **Database History**: All scans are saved to a local SQLite database (`nis2_platform.db`) for trend analysis.
- **Real-time Alerts**: Sends **Slack/Webhook notifications** immediately upon detecting CRITICAL issues.

### 🚀 Performance
- **10x Plugin Architecture (v2.1.0)**: Parallel scanning engine powered by `asyncio` and `httpx` (HTTP/2 support).
- **Asynchronous IO Core**: Non-blocking parallel execution for both network and compliance checks.

### 📊 Advanced Reporting
- **Console**: Color-coded summary.
- **JSON**: Machine-readable data for SIEM integration.
- **PDF**: Executive reports with visual graphs and governance gaps.
- **HTML**: Interactive dashboard.

## 🚀 Quick Start (Docker)
The easiest way to run the platform is using Docker.

### Option 1: Docker Compose (Recommended)
This starts the Web Dashboard and Database automatically.

```bash
# Clone the repository
git clone https://github.com/fabriziosalmi/nis2-checker.git
cd nis2-checker

# Start the platform
docker-compose up -d

# Access the dashboard at http://localhost:8000
```

### Option 2: Docker CLI (One-off Scan)
Run a single scan without the web interface.

```bash
docker run --rm \
  -v $(pwd)/config.yaml:/app/config.yaml \
  -v $(pwd)/targets.yaml:/app/targets.yaml \
  fabriziosalmi/nis2-checker
```

## 🐍 Installation (Python)

```bash
# 1. Clone the repository
git clone https://github.com/fabriziosalmi/nis2-checker.git
cd nis2-checker

# 2. Setup Virtual Environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install Browsers (for Screenshots)
playwright install chromium

# 5. Run the Scan
python3 -m nis2_checker.main
```

## Configuration

### `config.yaml`
Configure timeouts, enabled checks, and required headers.

```yaml
timeout: 10
checks:
  ssl_tls: true
  security_headers: true
  connectivity: true
ssl:
  min_version: "TLSv1.2"
headers:
  required:
    - "Strict-Transport-Security"
    - "X-Content-Type-Options"
```

### `targets.yaml`
Define your targets.

```yaml
targets:
  - url: "https://example.com"
    name: "Example"
  
  - url: "https://internal.api"
    name: "Internal API"
    auth_id: "INTERNAL_API" # Uses INTERNAL_API_TOKEN or INTERNAL_API_USER/_PASS env vars
```

## Usage

```bash
python -m nis2_checker.main --config config.yaml --targets targets.yaml
```

### Authentication
To scan protected targets, define `auth_id` in `targets.yaml` and set corresponding environment variables:

- **Bearer Token**: `export INTERNAL_API_TOKEN="your-token"`
- **Basic Auth**: 
  ```bash
  export INTERNAL_API_USER="username"
  export INTERNAL_API_PASS="password"
  ```

### Incident Reporting (Art. 23)
Use the interactive wizard to generate an early warning report for CSIRTs:
```bash
python3 -m nis2_checker.main report-incident
```
This generates a JSON file following CSIRT Italia/ENISA taxonomy in your current directory.

## 🐳 Docker Support
Run the checker anywhere without installing dependencies.

### Docker Usage
```bash
# Build
docker build -t nis2-checker .

# Run Scan
docker run -v $(pwd):/app nis2-checker scan --targets targets.yaml

# Run Incident Reporter (Interactive)
docker run -it -v $(pwd):/app nis2-checker report-incident
```

## 📊 Reporting
The tool automatically generates reports in the following formats based on the `--output` extension or configuration:

- **Console**: Default summary in the terminal.
- **JSON**: Detailed structure for programmatic processing.
- **Markdown**: GitHub-flavored summary, ideal for CI/CD job summaries.
- **CSV**: Spreadsheet-ready format for auditing tracking.
- **JUnit XML**: Integration with CI/CD test dashboards (GitLab/Jenkins).
- **PDF**: Executive summary with visual layout (requires `weasyprint`).

### Examples
```bash
# JSON (Default)
python3 -m nis2_checker.main scan --output report.json

# Markdown
python3 -m nis2_checker.main scan --output report.md

# CSV
python3 -m nis2_checker.main scan --output report.csv

# JUnit XML
python3 -m nis2_checker.main scan --output junit.xml
```

## 📜 Governance & Compliance (NIS2)

Achieving NIS2 compliance is not just about technical scans; it requires robust organizational governance. We provide a **[Governance Checklist](governance_checklist.md)** to help you track non-technical requirements.

### How to use the Governance Checklist
1.  **Download/Clone**: Keep the `governance_checklist.md` in your repository or export it to your internal documentation system (Confluence, SharePoint).
2.  **Prioritize**: Start with the **🔴 Critical Priority** items. These are "Must-Haves" to avoid immediate legal repercussions and ensure business continuity.
3.  **Assign & Track**: Use the checklist to assign tasks to specific departments (Legal, HR, IT) and track progress during monthly compliance reviews.
4.  **Audit Trail**: Use the checklist as a high-level index for your compliance evidence.

> **Note**: This tool and checklist are aids for compliance but do not replace legal advice or official certification.

## CI/CD

### GitHub Actions
The `.github/workflows/nis2.yml` workflow is available but **should be used with caution**.

> [!WARNING]
> **Do not run Nmap scans from public GitHub Runners.**
> Port scanning public targets from GitHub's infrastructure violates their Acceptable Use Policy and may get your account banned.
>
> **Recommendation**:
> *   Use **Self-Hosted Runners** inside your network.
> *   Run the tool via a VPN (e.g., **Tailscale**) or Proxy to reach internal targets safely.
> *   The workflow in this repo is manually disabled by default for safety.

### GitLab CI
The `.gitlab-ci.yml` pipeline runs on schedules. Configure CI/CD variables for secrets.
