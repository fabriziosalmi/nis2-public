<!--
  Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
  SPDX-License-Identifier: AGPL-3.0-only
  NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
-->

# Privacy Policy / Informativa privacy

*Last updated: 2026-04-30 — version 1.0*

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

When you `git clone` and `make prod` on your own infrastructure, **you become the sole data controller** (Art. 4(7) GDPR) for the personal data processed by your instance:

- Registered user accounts (email, full name, hashed password, locale preference)
- Asset inventories and scan targets you supply
- Scan results and findings
- Audit log entries (90-day retention, configurable)
- Authentication tokens (session cookies, refresh tokens, CSRF tokens)
- Any scan-side content that incidentally captures personal data (e.g. emails surfaced by the secrets scanner)

The maintainer:
- Is **not** a data processor for your instance — there is no contract under Art. 28 between you and the maintainer for self-hosted deployments
- Provides this software *as is* under AGPL-3.0 with no warranty (see [LICENSE](https://github.com/fabriziosalmi/nis2-public/blob/main/LICENSE))
- Receives **no telemetry**, no scan data, no user data from your instance — see the architectural commitment in the [README](https://github.com/fabriziosalmi/nis2-public#deployment-designed-for-on-premise)

You are obliged to:
- Publish your own privacy notice (you may use this template as a starting point — adapt the controller, recipients, retention, and rights sections to your own facts)
- Maintain your records of processing (Art. 30) and conduct a DPIA (Art. 35) if your processing meets the criteria
- Notify your users in case of breach (Art. 33-34) on your timeline, not the maintainer's

## 8. Updates

We may update this notice from time to time — material changes are reflected in the *Last updated* date at the top and announced in the `CHANGELOG.md` of the project.

## 9. Contact

For any privacy-related question, request, or complaint about the **public maintainer-operated surfaces** described above:

**Salmi Fabrizio** — Via Sapri 9, 16134 Genova, Italy — [fabrizio.salmi@gmail.com](mailto:fabrizio.salmi@gmail.com)

For self-hosted instances, contact whoever runs that instance — not the maintainer of this open-source project.
