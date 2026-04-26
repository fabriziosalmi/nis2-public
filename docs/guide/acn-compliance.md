# Italy: D.Lgs 138/2024 and ACN

This page documents the Italian national transposition module. The NIS2 Directive (EU 2022/2555) is transposed in Italy via D.Lgs 138/2024. The national authority is ACN (Agenzia per la Cybersicurezza Nazionale).

## Regulatory framework

| Reference | Description | Platform status |
|-----------|-------------|----------------|
| **D.Lgs 138/2024** | Italian NIS2 transposition | Supported |
| **Determina ACN 127434/2026** | Technical security baseline measures (deadline: July 2027) | Supported |
| **Determina ACN 127437/2026** | Relevant vendor inventory (Art. 18) | Supported |
| **ACN BIA template** | Standardized Business Impact Analysis | Supported (ready for ACN template at publication) |

## Art. 21 mapping (D.Lgs 138/2024)

The governance checklist covers all 10 subsections of Art. 21 with 30 weighted items:

| Art. 21 subsection | Scope | Items |
|--------------------|-------|-------|
| (a) Risk analysis policies | Risk assessment methodology, periodic updates | 3 |
| (b) Incident handling | Detection, response, CSIRT notification, lessons learned | 3 |
| (c) Business continuity | BCP, DRP, backup, periodic testing | 3 |
| (d) Supply chain security | Vendor assessment, contracts, supplier monitoring | 3 |
| (e) Secure acquisition and development | Secure SDLC, code review, vulnerability management | 3 |
| (f) Effectiveness assessment | Internal audits, security KPIs, penetration testing | 3 |
| (g) Cyber hygiene and training | Awareness, phishing simulation, team competencies | 3 |
| (h) Cryptography | Crypto policy, key management, algorithms | 3 |
| (i) Human resources security | Onboarding/offboarding, screening, privileged access | 3 |
| (j) Authentication and access control | MFA, RBAC, PAM, SSO, access logging | 3 |

## Determina 127434/2026 -- Baseline security measures

Determina 127434 defines the baseline security measures that NIS2 entities must implement **by July 2027**.

The platform provides continuous automated verification of the following technical measures:

| Measure category | Automated checks |
|-----------------|-----------------|
| Secure service configuration | TLS version, cipher suite, HSTS, CSP, X-Frame-Options |
| Certificate management | Chain validation, OCSP, CT logs, key strength, expiry monitoring |
| DNS security | DNSSEC, SPF, DMARC, DKIM, zone transfer protection |
| Network access control | Port exposure analysis (14 critical ports), SSH hardening |
| Monitoring and detection | Secrets exposure, version disclosure, WAF/CDN detection |
| Data-in-transit protection | TLS enforcement, weak protocol probing, certificate pinning |

### Operational deadlines

| Deadline | Requirement |
|----------|------------|
| **July 2027** | Baseline security measures implementation |
| **Continuous** | Periodic effectiveness verification |

## Determina 127437/2026 -- Relevant vendors (Art. 18)

Determina 127437 requires the inventory of vendors relevant to supply chain security.

### Status: Implemented

The Vendor Risk Management module is live with the following features:

- Vendor inventory with criticality classification (1-4)
- Security assessment scoring (0-100)
- Contract tracking (SLA, audit rights, security clauses)
- Geographic location and data access level
- Certification tracking (ISO 27001, SOC2, CSA STAR)
- ACN Art. 18 relevance flagging
- ACN-compatible JSON export: `GET /api/v1/acn-export/art18`

The governance checklist also includes 3 items for Art. 21(d) supply chain policy.

## Business Impact Analysis (BIA)

### Status: Implemented

The BIA module is live. Integration with ACN's official template will be added at publication.

- Business process inventory with criticality levels (1-4)
- RTO/RPO/MTPD per process
- 5-dimension impact scoring
- Asset and vendor dependency mapping
- BCP/DRP gap detection
- ACN service classification (essential/important)
- ACN-compatible JSON export: `GET /api/v1/acn-export/bia`

## Incident reporting -- Art. 23 CSIRT

The platform supports structured information collection for CSIRT Italia notifications:

| Notification phase | Deadline | Platform support |
|-------------------|---------|-----------------|
| Early Warning | Within 24 hours | "Red Button" generates payload from 3 fields + asset inventory |
| Incident Notification | Within 72 hours | Structured report with EU taxonomy, IOCs, timeline |
| Final Report | Within 1 month | Aggregated data, impact assessment, lessons learned |

The platform generates structured reports compatible with ACN's notification requirements, simplifying evidence collection within the legally mandated deadlines.

> **Note:** The platform does not interface directly with the ACN portal. It generates structured data that the notification officer can enter manually or through ACN's official channels.

## NIS2 and GDPR separation

The platform clearly distinguishes between NIS2 controls and GDPR/ePrivacy controls:

| Scope | Checks | Regulation |
|-------|--------|-----------|
| **NIS2 / D.Lgs 138/2024** | TLS, DNS security, port exposure, certificate health, incident reporting, governance checklist | Directive (EU) 2022/2555 |
| **EU Privacy / GDPR Posture** | P.IVA, privacy policy, cookie banner | GDPR, ePrivacy Directive |

The two scopes are separated in the interface and in reports to prevent regulatory confusion.

## About this module

This module is an **open-source bridge** to facilitate NIS2 compliance for Italian entities. It does not replace ACN's official portals and templates, but streamlines the collection, verification, and export of data required for regulatory compliance.

For implementation support or a commercial license: [fabrizio.salmi@gmail.com](mailto:fabrizio.salmi@gmail.com)
