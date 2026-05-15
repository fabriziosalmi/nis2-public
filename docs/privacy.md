<!--
  Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
  SPDX-License-Identifier: AGPL-3.0-only
  NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
-->

# Privacy Policy / Informativa privacy

*Last updated: 2026-04-30 — version 1.1*

> **Scope of this notice.** This document covers (a) the **public maintainer-operated surfaces** of the project — the documentation site at `https://fabriziosalmi.github.io/nis2-public/` and direct contact via the email address listed below — and (b) provides a **template** that operators of self-hosted instances are expected to adapt for their own deployments (see *Self-hosted deployments* below).
>
> **You are reading the public-website notice when you visit:** `fabriziosalmi.github.io/nis2-public/*` or contact `fabrizio.salmi@gmail.com`.

## 1. Data controller (*titolare del trattamento*)

For the maintainer-operated surfaces:

- **Salmi Fabrizio** (sole proprietor — *libero professionista*)
- Registered address: Via Sapri 9, 16134 Genova, Italy
- VAT (P.IVA): IT 03072120995
- Email: [fabrizio.salmi@gmail.com](mailto:fabrizio.salmi@gmail.com)

A formal Data Protection Officer is not designated; the project does not meet any of the trigger conditions in Art. 37(1) GDPR (no large-scale systematic monitoring, no large-scale special-category processing).

## 2. What we process and why

### 2.1 Documentation website (`fabriziosalmi.github.io/nis2-public/`)

The documentation is statically generated and served by **GitHub Pages**. We do not run analytics, advertising trackers, or ourselves set any non-essential cookie. GitHub itself, as the hosting provider, may process the following technical data on its own behalf:

| Data | Purpose | Legal basis | Retention |
|---|---|---|---|
| IP address, User-Agent, request URL, timestamp | Web hosting (security, abuse mitigation, debugging) | Legitimate interest (Art. 6(1)(f)) — running a public website | Per [GitHub's privacy practices](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement) |

GitHub's processing is governed by [GitHub's Privacy Statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement). We do not aggregate, profile, or use this data ourselves.

The bilingual home page stores **one technical preference** in your browser via `localStorage`:

| Key | Value | Purpose | Why it is not a "cookie" under the e-Privacy Directive |
|---|---|---|---|
| `nis2-doc-locale` | `"en"` or `"it"` | Remember your chosen documentation language across visits | Strictly necessary for the user-explicitly-requested language preference (Art. 122 D.Lgs 196/2003 — exemption for "strictly necessary" technical storage) |

No consent banner is required for this single key because no non-essential cookies are set.

### 2.2 Direct contact via email

When you write to `fabrizio.salmi@gmail.com` (e.g. for a consultation request, dual-license inquiry, or bug report):

| Data | Purpose | Legal basis | Retention |
|---|---|---|---|
| Email address | Reply to your message | Legitimate interest (Art. 6(1)(f)) — answering a deliberate inquiry from you | Until the conversation is concluded + reasonable archival period (max. 24 months) for follow-up reference |
| Message content (including any data you include) | Same as above | Same | Same |

If your message leads to a paid engagement, processing for that engagement is then governed by the contract and applicable accounting / VAT-record-keeping retention obligations (typically 10 years under Italian fiscal law).

### 2.3 GitHub repository interactions

When you open an Issue, Pull Request, comment, or any public interaction on the GitHub repository, GitHub itself is the data controller for your activity. We see what GitHub publicly displays. We do not process this data outside the GitHub platform itself.

## 3. What we do NOT process

For the avoidance of doubt:

- We **do not** run web analytics (Google Analytics, Plausible, Matomo, Fathom, etc.) on the documentation site.
- We **do not** set advertising or tracking cookies.
- We **do not** sell, share, or transfer personal data to third parties for their independent marketing purposes.
- We **do not** transfer personal data outside the EEA except to the extent GitHub does so under its own legal frameworks (Standard Contractual Clauses + supplementary measures per *Schrems II*).
- The platform itself ships **zero outbound telemetry** — see [README — Deployment: designed for on-premise](https://github.com/fabriziosalmi/nis2-public#deployment-designed-for-on-premise).

## 4. Recipients

| Recipient | Why | Where |
|---|---|---|
| **GitHub, Inc.** (Microsoft) | Hosting of repo + Pages | USA + EU (SCC + supplementary measures) |
| **Google LLC** | Mail relay (Gmail) for `fabrizio.salmi@gmail.com` until migration to a proper professional address | USA + EU |

No other recipients.

## 5. Your rights (GDPR Art. 15-22)

You can exercise the following rights at any time by writing to [fabrizio.salmi@gmail.com](mailto:fabrizio.salmi@gmail.com):

- **Access** (Art. 15) — confirm whether we hold your data and obtain a copy
- **Rectification** (Art. 16) — correct inaccurate data
- **Erasure** (Art. 17) — request deletion ("right to be forgotten") subject to retention obligations
- **Restriction** (Art. 18) — limit processing pending verification
- **Portability** (Art. 20) — receive your data in a structured, machine-readable format
- **Object** (Art. 21) — object to processing based on legitimate interest

We will respond within one month (Art. 12(3)) and will not charge a fee for reasonable requests (Art. 12(5)).

You also have the right to lodge a complaint with the Italian Data Protection Authority — [Garante per la Protezione dei Dati Personali](https://www.garanteprivacy.it/) — or with your local supervisory authority.

## 6. Data breach notification

In the event of a personal data breach affecting the maintainer-operated surfaces, we will notify the *Garante* within 72 hours where required (Art. 33 GDPR) and notify affected data subjects without undue delay where the breach is likely to result in a high risk to their rights and freedoms (Art. 34 GDPR).

## 7. Self-hosted deployments — you are the data controller

When you `git clone` and `make prod` on your own infrastructure, **you become the sole data controller** (Art. 4(7) GDPR) for the personal data processed by your instance.

### 7.1 What your instance processes (data inventory)

| Category | What | Where it lives | Default retention |
|---|---|---|---|
| Account data | email, full name, bcrypt-hashed password, locale preference, `password_changed_at`, `is_active` | `users` table | until user-initiated erasure (DELETE `/api/v1/auth/me`) |
| Membership data | `user_id`, `organization_id`, `role` (`owner`/`admin`/`auditor`/`viewer`) | `memberships` table | until user erasure or org deletion |
| Authentication state | httpOnly access + refresh JWT cookies, JS-readable CSRF cookie, JTI revocation list | browser cookies + `revoked_tokens` table | access: 15 min; refresh: 7 days; revoked JTIs pruned hourly past expiry |
| Audit log | `user_id` (nullable post-erasure), `action`, `resource_type`, `resource_id`, **`ip_address`**, **`user_agent`**, `created_at`, optional `metadata` JSON | `audit_logs` table | 90 days, configurable via `AUDIT_LOG_RETENTION_DAYS` |
| Password-reset tokens | `user_id`, `token_hash` (SHA-256), `expires_at`, `used_at` | `password_reset_tokens` table | 30 min TTL; pruned hourly post-expiry |
| Asset inventory | domain / IP / CIDR records and tags supplied by the user | `assets` table | until user-initiated deletion |
| Scan results | per-scan rollups, raw `scan_results` rows, deduplicated `findings` | `scans`, `scan_results`, `findings` tables | until user-initiated deletion (no automatic purge) |
| API keys | hashed key, name, scopes, last-used timestamp | `api_keys` table | until revoked |

### 7.2 IP address and User-Agent in `audit_logs`

Every successful state-changing request (Pre-`AuditMiddleware` v2.4.x) writes an `audit_logs` row that includes the originating **IP address** and **User-Agent**. Both are personal data when they relate to an identifiable person.

- **Legal basis** — Art. 6(1)(f) legitimate interest in maintaining a forensic trail of administrative actions on tenant data, with a documented retention ceiling. Art. 32 GDPR (security of processing) makes this trail expected for any system processing organisational compliance data.
- **Pseudonymisation on erasure** — when a user invokes `DELETE /api/v1/auth/me`, their `audit_logs` rows are not deleted (the audit trail is the controller's legitimate interest under Art. 89(1)). Instead: `user_id` is set to NULL, `ip_address` is replaced with `127.0.0.1`, `user_agent` is replaced with `[erased]`, and `details` (a JSONB field that may contain linkable UUIDs such as org or resource IDs) is set to NULL. The `action`, `resource_type`, `resource_id`, and `created_at` columns survive so the event chain remains intact for forensic purposes without attributing the event to the erased subject.
- **Retention** — default 90 days. Set `AUDIT_LOG_RETENTION_DAYS` to your own jurisdiction's requirement. A daily Celery beat job (`cleanup_expired_auth_records`) prunes rows — including pseudonymised ones — once their `created_at` age exceeds the ceiling.
- **GDPR Art. 17 vs NIS2 Art. 21 explicit resolution** — the platform resolves the tension between the right to erasure and the NIS2 audit-trail obligation through pseudonymisation: the event is retained in unlinkable form, satisfying both the GDPR storage-limitation principle (Art. 5(1)(e)) and the NIS2 requirement that audit evidence be available during the retention window. Operators using the platform for security-incident management should raise `AUDIT_LOG_RETENTION_DAYS` to ≥ 365 (NIS2 Art. 21 recommends evidence retention of at least 12 months); this does not conflict with GDPR because the retained rows are pseudonymised post-erasure.

### 7.3 Outbound network calls during scans

The scanner makes **direct DNS, TLS, HTTP, and TCP connections to the targets the user configures**. These are by definition personal data flows when the targets resolve to identifiable persons (e.g. an individual's mail server, a freelancer's homepage). Beyond the targets themselves, the scanner also queries the following **third-party services** that the deployer must disclose to data subjects:

| Service | Purpose | Data sent | Provider | Data flow |
|---|---|---|---|---|
| `crt.sh` (Sectigo) | Certificate Transparency log lookup for subdomain enumeration | the domain being scanned | Sectigo Limited (USA / UK) | scanner → crt.sh over HTTPS |
| Public DNS resolvers (system-configured) | Name resolution for scan targets | the domain being scanned | the deployer's resolver chain (often Cloudflare 1.1.1.1, Google 8.8.8.8, ISP) | OS resolver |
| Target hosts | TLS / HTTP / port probes | source IP of the scanner pod, scanner User-Agent | the target's operator | direct connection |

If your deployment uses a corporate proxy or a dedicated egress IP, replace the rows above accordingly. **No telemetry leaves the platform**: there is no callback to the maintainer, no error-reporting service, no analytics endpoint.

### 7.4 PII captured incidentally by the scanner

Some scanner modules surface evidence that may itself be personal data:

- **Secrets scanner** — pattern matches that look like AWS keys, JWTs, GitHub tokens, etc. are stored as the *finding evidence*. If a leaked secret happens to be shaped like an email address (e.g. `noreply@example.com`), it lands in `findings.technical_detail` verbatim.
- **Subdomain enumeration** — `crt.sh` returns FQDNs that may identify individual employees (e.g. `john-laptop.corp.example.com`).
- **Port / banner scans** — service banners can echo internal hostnames or admin email addresses.

The dashboard surfaces an in-product GDPR notice on the Findings page (`v2.5.4`) reminding the operator that they are the controller for this evidence and must apply the same retention / sharing care as for the underlying personal data.

### 7.5 What the maintainer is *not*

The maintainer:
- Is **not** a data processor for your instance — there is no contract under Art. 28 between you and the maintainer for self-hosted deployments
- Provides this software *as is* under AGPL-3.0 with no warranty (see [LICENSE](https://github.com/fabriziosalmi/nis2-public/blob/main/LICENSE))
- Receives **no telemetry**, no scan data, no user data from your instance — see the architectural commitment in the [README](https://github.com/fabriziosalmi/nis2-public#deployment-designed-for-on-premise)

### 7.6 Your obligations

You are obliged to:
- Publish your own privacy notice (you may use this template as a starting point — adapt the controller, recipients, retention, and rights sections to your own facts)
- Maintain your records of processing (Art. 30) and conduct a DPIA (Art. 35) if your processing meets the criteria
- Notify your users in case of breach (Art. 33-34) on your timeline, not the maintainer's
- Disclose the third-party data flows in §7.3 to your users — `crt.sh` in particular is a transfer to a non-EEA controller and may require either contractual safeguards or disabling of subdomain enumeration
- Configure `AUDIT_LOG_RETENTION_DAYS` to match your own retention obligations

## 8. Updates

We may update this notice from time to time — material changes are reflected in the *Last updated* date at the top and announced in the `CHANGELOG.md` of the project.

## 9. Contact

For any privacy-related question, request, or complaint about the **public maintainer-operated surfaces** described above:

**Salmi Fabrizio** — Via Sapri 9, 16134 Genova, Italy — [fabrizio.salmi@gmail.com](mailto:fabrizio.salmi@gmail.com)

For self-hosted instances, contact whoever runs that instance — not the maintainer of this open-source project.
