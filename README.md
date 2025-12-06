# NIS2 Compliance Checker

A modular, automated system to verify NIS2 compliance (Basic Cyber Hygiene) for URLs and IPs.

## Features

### 🛡️ Core Compliance
- **Connectivity Checks**: Verifies target reachability (IPv4/IPv6).
- **SSL/TLS Compliance**: Checks for minimum TLS version (1.2/1.3), certificate validity, and expiry.
- **Security Headers**: Verifies HSTS, X-Content-Type-Options, X-Frame-Options, CSP.

### 🧠 Strategic Intelligence (New in v0.4.0)
- **Domain Continuity (WHOIS)**: Alerts if domain expiration is < 30 days (Anti-Disaster).
- **Secrets Detection**: Passive scan for leaked AWS keys, Private keys, and API tokens in HTML/JS.
- **Supply Chain (Tech Stack)**: Fingerprints and alerts on obsolete Nginx/PHP/jQuery versions.
- **Visual Evidence**: Captures real-time **Screenshots** of targets for audit trails.
- **Holistic DNS**: Validates **SPF**, **DMARC**, and **DNSSEC** implementation.

### ⚙️ Infrastructure Audit
- **Nmap Vulnerability Scan**: integration with `vulners` script to detect **CVEs** on open ports.
- **Service Hardening**: Detects SSH password auth, cleartext HTTP management ports, and insecure RDP/SMB.

### 📈 Persistence & Alerting
- **Database History**: All scans are saved to a local SQLite database (`nis2_platform.db`) for trend analysis.
- **Real-time Alerts**: Sends **Slack/Webhook notifications** immediately upon detecting CRITICAL issues.

### 🚀 Performance
- **AsyncIO Core**: Parallel scanning engine capable of handling hundreds of targets concurrently.

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

## 🐳 Docker Support
Run the checker anywhere without installing dependencies manually.

```bash
# Build
docker build -t nis2-checker .

# Run (mount config and targets)
docker run --rm \
  -v $(pwd)/config.yaml:/app/config.yaml \
  -v $(pwd)/targets.yaml:/app/targets.yaml \
  nis2-checker
```

## 📊 Reporting
The tool generates multiple report formats:
- **Console**: Color-coded output.
- **JSON**: For automated processing (`report.json`).
- **HTML**: Professional dashboard (`report.html`).

Enable them in `config.yaml`:
```yaml
report:
  json: true
  html: true
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
