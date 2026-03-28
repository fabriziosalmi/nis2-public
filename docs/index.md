---
layout: home

hero:
  name: "NIS2 Platform"
  text: "Compliance Scanning & Management"
  tagline: "Full-stack SaaS platform for automated NIS2 Art. 21 compliance scanning, finding management, and report generation."
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
  - title: Admin Dashboard
    details: 16-page Next.js dashboard for scans, assets, findings, compliance matrix, reports, and team management.
  - title: Automated Scanner
    details: 50+ compliance checks covering ports, TLS, DNS, HTTP headers, legal pages, secrets, WHOIS, and WAF detection.
  - title: Report Generation
    details: Export findings as PDF, JSON, or CSV. Reports generated asynchronously via Celery workers.
  - title: Scheduled Scans
    details: Configure recurring scans with cron expressions via Celery Beat. Compare results across scan runs.
  - title: Multi-Tenant Organizations
    details: JWT authentication with RBAC (admin, auditor, viewer). Isolated data per organization.
  - title: NIS2 Art. 21 Compliance Matrix
    details: Map scanner findings to NIS2 directive articles. Track compliance posture over time.
---
