# NIS2 Compliance Checker

A modular, automated system to verify NIS2 compliance (Basic Cyber Hygiene) for URLs and IPs.

## Features

- **Connectivity Checks**: Verifies target reachability.
- **SSL/TLS Compliance**: Checks for minimum TLS version, certificate validity, and expiry.
- **Security Headers**: Verifies presence of critical security headers (HSTS, X-Content-Type-Options, etc.).
- **Infrastructure Audit**: Checks for SSH password auth, deprecated TLS, and open management ports using Nmap.
- **Network Discovery**: Scans entire subnets (CIDR) with low-impact settings.
- **Governance Checklist**: Includes a [manual checklist](governance_checklist.md) for NIS2 governance priorities.
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

## CI/CD

### GitHub Actions
The `.github/workflows/nis2.yml` workflow runs daily. Add secrets to your repository settings to support authenticated scans.

### GitLab CI
The `.gitlab-ci.yml` pipeline runs on schedules. Configure CI/CD variables for secrets.
