# NIS2 Compliance Checker

A modular, automated system to verify NIS2 compliance (Basic Cyber Hygiene) for URLs and IPs.

## Features

- **Connectivity Checks**: Verifies target reachability.
- **SSL/TLS Compliance**: Checks for minimum TLS version, certificate validity, and expiry.
- **Security Headers**: Verifies presence of critical security headers (HSTS, X-Content-Type-Options, etc.).
- **Infrastructure Audit**: Uses Nmap to check for:
    - SSH Password Authentication (Compliance Violation)
    - Deprecated TLS Versions (1.0/1.1)
    - Open Management Ports (Cleartext HTTP)
    - Windows RDP Encryption & SMB Signing
- **Extended Compliance Checks**:
    - **Email Security**: SPF and DMARC verification.
    - **DNS Security**: DNSSEC validation.
- **Advanced Reporting**:
    - **Console**: Summary output.
    - **JSON**: Detailed machine-readable report.
    - **HTML**: Visual dashboard with pass/fail badges.
    - **PDF**: Professional management report (via WeasyPrint).
- **Governance Checklist**: Integrated manual checklist for non-technical NIS2 requirements.
- **Dockerized**: Ready-to-run Docker image with all dependencies (Nmap, WeasyPrint).
- **Secure**: No hardcoded secrets, runs as non-root user. priorities.
- **Authentication Support**: Supports Basic Auth and Bearer Tokens via environment variables for secure scanning.
- **Reporting**: Console output and JSON reports.
- **CI/CD Integration**: Ready-to-use GitHub Actions and GitLab CI pipelines.

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/nis2-checker.git
cd nis2-checker

# Install dependencies
pip install -r requirements.txt
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
The `.github/workflows/nis2.yml` workflow runs daily. Add secrets to your repository settings to support authenticated scans.

### GitLab CI
The `.gitlab-ci.yml` pipeline runs on schedules. Configure CI/CD variables for secrets.
