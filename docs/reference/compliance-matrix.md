# NIS2 Compliance Matrix

The platform covers all ten sub-paragraphs (a) through (j) of NIS2 Art. 21, plus the Art. 23 incident reporting lifecycle and Art. 18 supply chain requirements.

**Legend**:
- **Implemented** — fully automated with no manual step required on the platform side
- **Partial** — automated checks cover the technically observable surface; organisational controls require human verification in the governance checklist
- **Manual** — the directive explicitly requires human judgement; automation cannot substitute

---

## Art. 21 — Risk Management Measures

| Sub-paragraph | Scope | Status | Platform implementation |
|---|---|---|---|
| (a) Risk analysis and information security policies | Methodology, periodic updates, risk register | Partial | Governance checklist + `POST /governance/sync-risk` escalates checklist items when HIGH/CRITICAL scanner findings are open; `GET /governance/risk-summary` returns risk summary by article |
| (b) Incident handling | Detection, response, containment, CSIRT notification | Implemented | Incident module with Art. 23 lifecycle; Celery Beat checks every 15 min and dispatches alerts at 24 h / 72 h / 1-month thresholds with Redis-backed deduplication |
| (c) Business continuity | BCP, DRP, backup policy, periodic testing | Implemented (manual verification) | BIA module — RTO/RPO/MTPD per process, impact scoring (financial, operational, reputational, regulatory, safety), dependency mapping, gap detection |
| (d) Supply chain security | Vendor assessment, contracts, audit rights | Implemented | Vendor Risk module with documented 100-point scoring formula (certification, data access, audit recency, geographic location, security clauses); auditor-accessible formula at `GET /vendors/score-formula`; ACN Art. 18 relevance flagging |
| (e) Secure acquisition and development | SDLC, vulnerability management, code review | Partial | Technical validation engine (TLS, HTTP headers, port scanning, secrets detection) + governance checklist for organisational SDLC controls |
| (f) Effectiveness assessment | Internal audits, KPIs, penetration testing | Partial | Scan comparison for trend analysis, compliance score over time; governance checklist for formal audit requirements |
| (g) Cyber hygiene and training | Awareness programmes, phishing simulation | Manual | Governance checklist — human verification required by directive design |
| (h) Cryptography and key management | Crypto policy, key lifecycle, TLS enforcement | Partial | Automated checks: TLS version, cipher suite, certificate expiry, chain trust, HSTS presence; governance checklist for key management policy |
| (i) Human resources security | Onboarding, offboarding, access reviews, screening | Manual | Governance checklist — human verification required by directive design |
| (j) Authentication and access control | MFA, RBAC, PAM, access logging | Implemented | TOTP MFA per user; role-based access (admin/auditor/viewer); per-request scoped API keys with `dual_auth_with_scope`; full audit log; RS256 JWT with JWKS endpoint; session integrity via refresh token rotation |

---

## Art. 23 — Incident Reporting (CSIRT)

| Phase | Deadline | Platform support |
|---|---|---|
| Early Warning | 24 hours from detection | `POST /incidents/{id}/early-warning` generates a CSIRT-ready JSON document; automated alert at 24 h breach and 2 h before |
| Incident Notification | 72 hours from detection | Structured notification form with EU taxonomy, IOCs, and timeline; automated alert at 72 h breach and 2 h before |
| Final Report | 1 month from detection | Aggregated impact assessment and lessons learned; automated alert at 1-month breach and 2 h before |

Alerts are dispatched through notification channels (email, webhook with HMAC-SHA256 signature, Slack). Submission to CSIRT Italia (`csirt.gov.it`) is a manual step — the platform produces the artefacts but does not push to the portal.

---

## Art. 18 — Supply Chain Security

| Feature | Status |
|---|---|
| Vendor inventory with criticality classification (1–4) | Implemented |
| Security scoring 0–100 with documented formula | Implemented |
| Contract field tracking (SLA, audit rights, security clauses) | Implemented |
| Geographic location and data access level | Implemented |
| Certification tracking (ISO 27001, SOC 2, CSA STAR) | Implemented |
| Audit recency as a scoring factor | Implemented |
| ACN Art. 18 relevance flagging (Italy) | Implemented |
| ACN-compatible JSON export | Implemented (preliminary schema — pending official ACN template) |

---

## National Transposition — Italy (D.Lgs 138/2024)

| Reference | Coverage |
|---|---|
| D.Lgs 138/2024 | Art. 21 cross-references in governance checklist |
| Determina ACN 127434/2026 | Technical baseline references in compliance matrix |
| Determina ACN 127437/2026 | Vendor inventory with ACN-specific fields |
| ACN compliance deadlines | Real-time countdowns: CSIRT referent (Dec 2026), 24h notification obligation (Jan 2027), baseline measures (Jul 2027) |
| ACN-compatible export | `GET /acn-export/art18` (vendor inventory), `GET /acn-export/bia` (BIA) |

The ACN export schema is preliminary. The official *modello di categorizzazione* announced by ACN has not been published as of v2.5.11. The current export is a best-effort structural mapping based on Determina 127437/2026 and will be updated once the official template is available.

---

## What the Platform Does Not Replace

The platform does not replace:
- A CISO or qualified security professional
- An internal audit programme or formal penetration test
- Legal review of your specific D.Lgs 138/2024 obligations and entity classification
- Direct engagement with ACN for registration and formal compliance submissions
- Board-level governance decisions and security budget allocation

The governance checklist tracks the items that require these human processes. The compliance matrix and scanner findings inform those processes but do not substitute for them.
