# Configuration

## Global Settings (`config.yaml`)
Configure timeouts, enabled checks, and required headers.

```yaml
timeout: 10
checks:
  ssl_tls: true
  security_headers: true
  connectivity: true
  ssh_password: true
  tls_deprecated: true
  http_cleartext: true
  windows_rdp: true
  windows_smb: true
report:
  json: true   # Generate JSON report (nis2_report.json)
  html: true   # Generate HTML dashboard (nis2_report.html)
  pdf: true    # Generate PDF report (report.pdf)

nmap:
  enabled: true
  vuln_scan_enabled: true # NEW: Scan for CVEs using vulners script
  timing: 3 # 0-5 (0=paranoid, 3=normal, 5=insane)
  discovery: true # Enable ping scan for CIDR targets
  ports:
    ssh: 22
    https: 443
    http_mgmt: [80, 8080]
  checks:
    ssh_password: true
    tls_deprecated: true
    http_cleartext: true

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

headers:
  required:
    - "Strict-Transport-Security"
    - "X-Content-Type-Options"
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
