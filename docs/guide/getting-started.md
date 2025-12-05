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

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/nis2-checker.git
cd nis2-checker

# Install dependencies
pip install -r requirements.txt
# Install Nmap (required for infrastructure audit)
# macOS: brew install nmap
# Linux: sudo apt-get install nmap
```

## Quick Start
```bash
python -m nis2_checker.main --config config.yaml --targets targets.yaml
```
