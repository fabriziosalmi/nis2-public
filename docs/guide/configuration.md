# Configuration

## Global Settings (`config.yaml`)
Configure timeouts, enabled checks, and required headers.

```yaml
# Timeout for requests in seconds
timeout: 10

# Compliance checks
checks:
  connectivity: true
  ssl_tls: true
  security_headers: true
  dns_checks: true
  whois_check: true
  evidence: true

# SSL/TLS Requirements
ssl:
  min_version: "TLSv1.2"
  check_expiry: true
  expiry_warning_days: 30

# Required Security Headers
headers:
  required:
    - "Strict-Transport-Security"
    - "X-Content-Type-Options"
    - "X-Frame-Options"

# Infrastructure Audit (Nmap)
nmap:
  enabled: true
  timing: 3 # 0-5 (0=paranoid, 1=sneaky, 2=polite, 3=normal, 4=aggressive, 5=insane)
  discovery: true # Enable ping scan for CIDR targets
  ports:
    ssh: 22
    https: 443
    http_mgmt: [80, 8080]
    rdp: 3389
    smb: 445
  checks:
    ssh_password: true
    tls_deprecated: true
    http_cleartext: true
    windows_rdp: true
    windows_smb: true
    dns_checks: true

# DNS Security Checks
dns:
  timeout: 5
  checks:
    email_security: true # SPF, DMARC
    dns_security: true   # DNSSEC

# Alerting / Notifications
notifications:
  slack_webhook: "https://hooks.slack.com/services/YOUR/WEBHOOK"
  alert_on: ["FAIL"] # Trigger alert only on critical failures

# Reporting
report:
  format: "console" # console, json, pdf, html
  output_file: "report.json"
```

## Targets (`targets.yaml`)
Define your targets using URLs, IPs, or CIDR notation.

```yaml
targets:
  - url: "https://example.com"
    name: "Example Web"
    type: "web"
  
  - ip: "192.168.1.10"
    name: "Internal Server"
    type: "ssh"

  - ip: "192.168.1.0/24"
    name: "Office Network"
    type: "generic" # Scans all hosts in subnet
```

### Target Types
- `web` / `https`: Runs SSL, Headers, and Web Port checks.
- `ssh`: Runs SSH Authentication checks.
- `windows`: Runs RDP and SMB security checks.
- `generic`: Runs a broad set of safe checks.
