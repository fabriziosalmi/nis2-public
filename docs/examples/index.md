# Examples

Real-world usage examples for the NIS2 Scanner.

## Basic Scan

Simple scan of a single domain:

```yaml
# basic-scan.yaml
project_name: "Basic Security Scan"
scan_timeout: 10
concurrency: 10

targets:
  domains:
    - "example.com"

features:
  dns_checks: true
  whois_checks: true

compliance_profile: "standard_nis2"
```

Run:
```bash
CONFIG_FILE=./basic-scan.yaml docker-compose up -d
docker-compose exec scanner python -m nis2scan.cli scan
```

## Production Setup

Comprehensive production infrastructure scan:

```yaml
# production-scan.yaml
project_name: "Production Infrastructure Audit"
scan_timeout: 30
concurrency: 20

targets:
  domains:
    - "mycompany.com"
    - "www.mycompany.com"
    - "api.mycompany.com"
    - "app.mycompany.com"
  ip_ranges:
    - "203.0.113.0/24"

features:
  dns_checks: true
  whois_checks: true

compliance_profile: "strict"
```

Run with full monitoring:
```bash
CONFIG_FILE=./production-scan.yaml \
docker-compose -f docker-compose.yml -f docker-compose.grafana.yml up -d

docker-compose exec scanner python -m nis2scan.cli scan
```

## Multi-Target Scan

Scan multiple environments:

```yaml
# multi-env-scan.yaml
project_name: "Multi-Environment Scan"
scan_timeout: 15
concurrency: 15

targets:
  domains:
    - "dev.example.com"
    - "staging.example.com"
    - "production.example.com"
    - "api-dev.example.com"
    - "api-staging.example.com"
    - "api-prod.example.com"

features:
  dns_checks: true
  whois_checks: true

compliance_profile: "standard_nis2"
```

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/security-scan.yml
name: NIS2 Security Scan

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout
        uses: actions/checkout@v3
      
      - name: Create config
        run: |
          cat > scan-config.yaml <<EOF
          project_name: "CI Security Scan"
          targets:
            domains:
              - "${{ secrets.DOMAIN }}"
          features:
            dns_checks: true
            whois_checks: true
          compliance_profile: "standard_nis2"
          EOF
      
      - name: Run scan
        run: |
          CONFIG_FILE=./scan-config.yaml docker-compose up -d
          docker-compose exec -T scanner python -m nis2scan.cli scan
      
      - name: Upload reports
        uses: actions/upload-artifact@v3
        with:
          name: nis2-reports
          path: reports/
      
      - name: Cleanup
        if: always()
        run: docker-compose down -v
```

### GitLab CI

```yaml
# .gitlab-ci.yml
security-scan:
  image: docker:latest
  services:
    - docker:dind
  
  script:
    - docker-compose up -d
    - docker-compose exec -T scanner python -m nis2scan.cli scan
  
  artifacts:
    paths:
      - reports/
    expire_in: 30 days
  
  schedule:
    - cron: "0 2 * * *"
```

## Scheduled Scans

### Cron Job

```bash
# /etc/cron.d/nis2-scan
0 2 * * * user cd /opt/nis2-public && CONFIG_FILE=./config_prod.yaml docker-compose exec -T scanner python -m nis2scan.cli scan
```

### Systemd Timer

```ini
# /etc/systemd/system/nis2-scan.timer
[Unit]
Description=Daily NIS2 Security Scan

[Timer]
OnCalendar=daily
OnCalendar=02:00
Persistent=true

[Install]
WantedBy=timers.target
```

```ini
# /etc/systemd/system/nis2-scan.service
[Unit]
Description=NIS2 Security Scan

[Service]
Type=oneshot
WorkingDirectory=/opt/nis2-public
Environment="CONFIG_FILE=./config_prod.yaml"
ExecStart=/usr/bin/docker-compose exec -T scanner python -m nis2scan.cli scan
```

Enable:
```bash
systemctl enable nis2-scan.timer
systemctl start nis2-scan.timer
```

## Custom Reporting

### JSON Processing

```bash
# Extract compliance score
docker-compose exec scanner python -m nis2scan.cli scan
jq '.compliance_score' reports/nis2_report_*.json

# List critical findings
jq '.findings[] | select(.severity == "CRITICAL")' reports/nis2_report_*.json
```

### Slack Notifications

```bash
#!/bin/bash
# notify-slack.sh

# Run scan
docker-compose exec -T scanner python -m nis2scan.cli scan

# Get latest report
REPORT=$(ls -t reports/nis2_report_*.json | head -1)
SCORE=$(jq -r '.compliance_score' "$REPORT")
FINDINGS=$(jq -r '.findings | length' "$REPORT")

# Send to Slack
curl -X POST $SLACK_WEBHOOK \
  -H 'Content-Type: application/json' \
  -d "{
    \"text\": \"NIS2 Scan Complete\",
    \"attachments\": [{
      \"color\": \"$([ $SCORE -gt 70 ] && echo good || echo danger)\",
      \"fields\": [
        {\"title\": \"Compliance Score\", \"value\": \"$SCORE/100\", \"short\": true},
        {\"title\": \"Findings\", \"value\": \"$FINDINGS\", \"short\": true}
      ]
    }]
  }"
```

## Next Steps

- [Configuration Guide](/guide/configuration) - Customize your scans
- [Docker Guide](/guide/docker) - Advanced Docker usage
- [Reference](/reference/config-schema) - Full configuration options
