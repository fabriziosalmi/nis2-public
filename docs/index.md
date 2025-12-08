---
layout: home

hero:
  name: NIS2 Compliance Scanner
  text: Automated Security & Compliance Auditing
  tagline: Comprehensive NIS2 Directive compliance scanning with detailed reporting and evidence collection
  actions:
    - theme: brand
      text: Get Started
      link: /guide/getting-started
    - theme: alt
      text: Quick Start
      link: /guide/quick-start
    - theme: alt
      text: View on GitHub
      link: https://github.com/fabriziosalmi/nis2-public

features:
  - icon: 🔍
    title: Comprehensive Scanning
    details: Automated checks for ports, TLS/SSL, HTTP headers, DNS security, and more
  
  - icon: 📊
    title: Multiple Report Formats
    details: Generate HTML, JSON, and Markdown reports with detailed findings
  
  - icon: 🐳
    title: Docker Ready
    details: Easy deployment with Docker and docker-compose, optional Grafana dashboards
  
  - icon: 🔐
    title: Security Focused
    details: Detect secrets, check WAF/CDN protection, monitor domain expiry
  
  - icon: 🇮🇹
    title: Italian Compliance
    details: Built-in checks for Italian legal requirements (P.IVA, privacy, cookies)
  
  - icon: 📈
    title: Prometheus Integration
    details: Export metrics for monitoring and alerting with Prometheus and Grafana
---

## Quick Example

```bash
# Quick start with Docker
CONFIG_FILE=./test_config.yaml docker-compose up -d

# Run a scan
docker-compose exec scanner python -m nis2scan.cli scan

# View reports
open http://localhost:8000
```

## Why NIS2 Scanner?

The NIS2 Directive requires organizations to implement robust cybersecurity measures. This scanner automates compliance checks and generates audit-ready reports to help you:

- ✅ Identify security vulnerabilities
- ✅ Verify compliance with NIS2 requirements
- ✅ Generate evidence for audits
- ✅ Monitor security posture over time
- ✅ Integrate with existing monitoring tools

## Features at a Glance

| Feature | Description |
|---------|-------------|
| **Port Scanning** | Detect exposed critical services (DB, SMB, RDP, etc.) |
| **TLS/SSL Checks** | Verify certificate validity and configuration |
| **Security Headers** | Check for HSTS, CSP, and other security headers |
| **DNS Security** | Validate DNSSEC and check for zone transfers |
| **Secrets Detection** | Scan for exposed API keys, tokens, and credentials |
| **WHOIS Monitoring** | Track domain expiration dates |
| **WAF/CDN Detection** | Identify protective services |
| **Legal Compliance** | Italian P.IVA, privacy policy, cookie consent |

## Next Steps

<div class="tip custom-block" style="padding-top: 8px">

Ready to get started? Check out the [Getting Started Guide](/guide/getting-started) or jump straight to the [Quick Start](/guide/quick-start).

</div>
