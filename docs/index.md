---
layout: home

hero:
  name: "NIS2 Platform"
  text: "Bridge governance documentation and network reality."
  tagline: "Open-source GRC platform for NIS2 Directive (EU 2022/2555). Governance framework, technical validation, incident response, supply chain risk. Self-hosted, air-gapped compatible."
  image:
    src: /screenshot.png
    alt: "NIS2 Platform dashboard: total scans, compliance score, findings, monitored assets, and the welcome onboarding panel"
  actions:
    - theme: brand
      text: Get Started
      link: /guide/getting-started
    - theme: alt
      text: API Reference
      link: /reference/api
    - theme: alt
      text: Request Consultation
      link: mailto:fabrizio.salmi@gmail.com

features:
  - icon:
      src: /icons/governance.svg
    title: Governance Framework
    details: 30-item checklist cross-referenced to NIS2 Art. 21 sub-paragraphs (a)-(j), machine-readable. Compliance scoring, trend analysis, multi-tenant RBAC.
    link: /governance/checklist
    linkText: View checklist
  - icon:
      src: /icons/remediation.svg
    title: Remediation Engine
    details: 15+ structured playbooks for Nginx, Apache, Caddy, IIS. AI copilot via Ollama/OpenAI. Effort and cost estimation per finding.
    link: /reference/api
    linkText: API reference
  - icon:
      src: /icons/incident.svg
    title: Incident Response
    details: Full Art. 23 CSIRT lifecycle. "Red Button" generates Early Warning payload in seconds. 24h/72h/1month deadline tracking with countdown.
    link: /guide/acn-compliance
    linkText: Learn more
  - icon:
      src: /icons/supplychain.svg
    title: Supply Chain Risk
    details: Vendor inventory with 4-level criticality, security scoring, contract tracking, certification monitoring, Art. 18 ACN fields.
    link: /reference/api
    linkText: Vendors API
  - icon:
      src: /icons/bia.svg
    title: Business Impact Analysis
    details: Process inventory with RTO/RPO/MTPD. Five-dimension impact scoring. Asset and vendor dependency mapping. Automatic gap detection.
    link: /reference/api
    linkText: BIA API
  - icon:
      src: /icons/scanner.svg
    title: Technical Validation
    details: 30+ automated checks on TLS, DNS, HTTP headers, ports, certificates, and secrets. The probe that verifies if your policies are enforced on the network.
    link: /reference/scanner-checks
    linkText: View all checks
---
