---
layout: home

hero:
  name: "NIS2 Platform"
  text: "Compliance Scanning and Management"
  tagline: "Open-source platform for scanning infrastructure against NIS2 Directive Art. 21 requirements."
  actions:
    - theme: brand
      text: Get Started
      link: /guide/getting-started
    - theme: alt
      text: API Reference
      link: /reference/api
    - theme: alt
      text: Governance Checklist
      link: /governance/checklist

features:
  - title: Scanner
    details: Checks ports, TLS versions and ciphers, HTTP security headers, DNS records (DNSSEC, SPF, DMARC, AXFR), WHOIS expiry, cookie flags, SRI, secrets in page source, sensitive file exposure, security.txt, WAF/CDN detection, and Italian legal requirements (P.IVA, privacy policy, cookie banner).
  - title: Dashboard
    details: Next.js 15 frontend with pages for scans, assets, findings, compliance matrix, reports, schedules, team management, API keys, and settings.
  - title: Report Generation
    details: Export scan results as PDF, JSON, or CSV. Reports are generated asynchronously via Celery workers and downloaded when ready.
  - title: Scheduled Scans
    details: Set up recurring scans with cron expressions. Celery Beat dispatches scans on schedule. Compare findings between any two scans in an organization.
  - title: Multi-Tenant Organizations
    details: JWT authentication with role-based access (admin, auditor, viewer). Data is isolated per organization.
  - title: NIS2 Art. 21 Compliance Matrix
    details: Each scan produces a compliance_matrix mapping findings to NIS2 directive articles. The compliance page reads from the most recent completed scan.
---
