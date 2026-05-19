# NIS2 ↔ EU AI Act Crosswalk for Dual-Subject Deployers

> **Status:** Initial contribution per Issue #95 (accepted by @fabriziosalmi 2026-05-19).
> **Scope:** Deployer-side organizations subject to both NIS2 and EU AI Act high-risk obligations.
> **Italian routing:** D.Lgs 138/2024 + ACN-specific paths included.

---

## 1. Purpose and scope

This crosswalk addresses a structural blind spot in current EU compliance practice: **organizations subject to both NIS2 (as essential or important entities under Annex I) and the EU AI Act (as high-risk AI system deployers under Article 26)**. Without an explicit mapping between the two regimes, these dual-subject organizations end up maintaining parallel evidence stacks — duplicating governance documentation, monitoring telemetry, incident reporting workflows, and supplier oversight.

The duplication is not hypothetical. An Italian fintech deploying AI-driven credit decisioning is simultaneously:

- A NIS2 essential entity (financial services sector, Annex I.1.h),
- An EU AI Act Article 26 deployer of high-risk AI (Annex III §5.b — creditworthiness assessment),
- Subject to D.Lgs 138/2024 (Italian transposition of NIS2) and ACN reporting routing,
- Subject to AI Office and national market surveillance authority for the AI Act dimension.

Each regime demands risk management, monitoring, incident reporting, and supplier governance. The substance overlaps. The reporting paths and timelines differ. This document maps the overlap so an organization can satisfy both regimes from one operational backbone instead of two.

## 2. Overlap matrix

The following matrix shows the high-density overlap zones — controls where NIS2 obligations and EU AI Act high-risk deployer obligations require the same underlying operational practice.

| NIS2 obligation | NIS2 reference | EU AI Act obligation | EU AI Act reference | Platform anchor |
|---|---|---|---|---|
| Risk management policies for network and information systems | Art. 21.2(a) | Risk management system (continuous, documented, reviewed) | Art. 9 | G-01, G-02 |
| Incident handling | Art. 21.2(b) | Post-market monitoring + serious incident reporting | Art. 72, Art. 73 | G-04, G-05 |
| Business continuity, backup management, crisis management | Art. 21.2(c) | Resilience and accuracy requirements | Art. 15 | G-08, G-09 |
| Supply chain security | Art. 21.2(d) | Provider-deployer information flow + GPAI provider obligations | Art. 13, Art. 53 | G-11, G-12 |
| Security in network/information systems acquisition, development, maintenance | Art. 21.2(e) | Technical documentation + lifecycle | Art. 11, Annex IV | G-14, G-15 |
| Policies and procedures to assess effectiveness of cybersecurity risk management | Art. 21.2(f) | Internal audit of the AI management system | Art. 17 (via ISO 42001 Clause 9.2 if used) | G-17 |
| Basic cyber hygiene practices and cybersecurity training | Art. 21.2(g) | AI literacy obligation | Art. 4 | G-19, G-20 |
| Policies and procedures regarding cryptography | Art. 21.2(h) | Accuracy, robustness, cybersecurity for high-risk AI | Art. 15(4) | G-22 |
| Human resources security, access control policies, asset management | Art. 21.2(i) | Human oversight (deployer-side) | Art. 14, Art. 26(2) | G-24, G-25 |
| Use of multi-factor authentication, secured voice/video/text comms, emergency comms | Art. 21.2(j) | Operational use per instructions | Art. 26(1), Art. 26(4) | G-27, G-28 |
| Notification of significant incidents to CSIRT/competent authority | Art. 23 | Notification of serious incidents to market surveillance authority | Art. 73 | G-30 |

**Key reading:** every NIS2 Art. 21.2 sub-paragraph has a substantive counterpart in the EU AI Act for organizations deploying high-risk AI systems. The control catalog is not parallel — it is the same control catalog read against two regulatory regimes.

## 3. Where the regimes diverge

Three areas where dual-subject organizations cannot collapse the two regimes into one process:

### 3.1 Incident reporting timelines and routes

- **NIS2 Art. 23:** Early warning to CSIRT/competent authority within **24 hours** of becoming aware; incident notification within **72 hours**; final report within **one month**.
- **EU AI Act Art. 73 (serious incidents):** Notification to the market surveillance authority **immediately** (and in any event no later than **15 days** after awareness; **immediately and not later than 2 days** for incidents resulting in death of a person or serious harm).

A single incident affecting both regimes (e.g., a security breach that exposes AI training data and triggers an algorithmic discrimination event) requires **two notifications on two timelines to two different authorities**. The platform's G-30 anchor should route both, with separate timers.

### 3.2 Affected-party disclosure

- **NIS2:** No general public disclosure obligation beyond authority notification (recipients of services may need to be informed in some cases, per Art. 23.2).
- **EU AI Act Art. 26(11):** Deployers of high-risk AI must inform natural persons subject to the AI system's decision.

Dual-subject organizations need a parallel notification queue for affected persons in addition to authority notification.

### 3.3 Supplier oversight depth

- **NIS2 Art. 21.2(d):** Security of supply chain, including security-related aspects of relationships with direct suppliers and service providers.
- **EU AI Act Art. 26(4) + Art. 53:** Deployer must use the AI system per provider instructions; GPAI provider must disclose training data summary and provide downstream-deployer information.

The AI Act adds a layer of **provider-deployer information flow** that NIS2 does not require. For organizations consuming foundation models from a GPAI provider (Anthropic, OpenAI, Mistral, etc.), the AI Act Art. 53 obligations of the upstream provider create downstream documentation that the deployer must absorb and retain. This is operationally heavier than typical NIS2 vendor security questionnaires.

## 4. Italian-specific routing (D.Lgs 138/2024 and ACN)

For organizations subject to the Italian transposition of NIS2 — **D.Lgs 138/2024**, in force since 16 October 2024 — the routing differs in three respects from the generic EU NIS2 framework.

### 4.1 ACN (Agenzia per la Cybersicurezza Nazionale) as the competent authority

ACN is the central authority for cybersecurity incident reporting in Italy under D.Lgs 138/2024 (Art. 7-8 of the decree). Incident notification timelines align with NIS2 generic timelines (24h / 72h / 1 month) but the **portal and reporting format** are ACN-specific.

The platform's existing ACN routing in `packages/api/app/routers/governance.py` already handles the NIS2 leg. This crosswalk recommends extending the same routing layer to:

- Tag incidents that also trigger EU AI Act Art. 73 reporting.
- Surface the dual-notification requirement at intake.
- Maintain separate timers (24h ACN early warning vs immediate/15-day market surveillance authority notification).

### 4.2 Sectoral overlap with AGID and Banca d'Italia

Italian fintech entities are simultaneously regulated by:

- ACN (NIS2 cybersecurity dimension),
- Banca d'Italia (PSD2, DORA financial services dimension),
- AGID (e-IDAS, digital identity dimension where applicable),
- Future Italian AI Act market surveillance authority (Italy has yet to designate the body as of May 2026; AGID and ACN are both candidates per public consultation responses).

For the AI Act dimension specifically, until the Italian competent authority is designated, dual-subject organizations should default to the **AI Office** central coordination route and flag the open designation in their incident response procedure.

### 4.3 Article 26(6) deployer monitoring — Italian fintech case

A practical example clarifies the dual-subject burden. An Italian fintech (50-person Series A, deploys AI credit decisioning, NIS2 essential entity Annex I.1.h):

- **AI system in scope of Annex III §5.b** — creditworthiness assessment of natural persons.
- **NIS2 essential entity** — Art. 21.2 obligations apply, ACN notification under Art. 23 / D.Lgs 138/2024 Art. 7-8.
- **Article 26(6) deployer monitoring** — must monitor system operation, suspend if risk identified, keep logs.

Single incident scenario: the credit model exhibits drift causing systematic discrimination against a protected group. Discovery on a Tuesday morning.

| Action | Regime | Deadline | Authority | Platform anchor |
|---|---|---|---|---|
| Internal triage + incident classification | Both | Same hour | Internal | G-04 |
| Early warning notification | NIS2 / D.Lgs 138 Art. 7 | 24h | ACN | G-30 |
| Incident notification (preliminary) | NIS2 / D.Lgs 138 Art. 7 | 72h | ACN | G-30 |
| Serious incident notification (AI Act) | EU AI Act Art. 73 | Immediately / ≤15 days | Market surveillance authority (TBD Italy) | G-05 |
| Affected-person notification | EU AI Act Art. 26(11) | Without undue delay | Affected natural persons | G-26 |
| System suspension or override | EU AI Act Art. 26(5) | Immediate | Internal + provider notice | G-25 |
| Final NIS2 incident report | NIS2 / D.Lgs 138 | 1 month | ACN | G-30 |
| AI Act post-incident analysis + corrective action | EU AI Act Art. 72 + Art. 26(5) | Documented, ongoing | Internal + provider | G-17, G-25 |

Two regimes, one underlying incident, eight distinct workflow obligations. The crosswalk makes these explicit so that an organization can build the workflow once instead of twice.

## 5. How to use this crosswalk operationally

The recommended pattern for dual-subject organizations:

### 5.1 Single inventory, dual-tagged

Maintain a single AI system inventory (per ISO/IEC 42001 Clause 8.1 / EU AI Act Art. 11). Tag each system with:

- AI Act risk classification (prohibited / high-risk / limited-risk / minimal-risk / GPAI deployer status).
- NIS2 essential-entity scope (yes/no, with sector reference if applicable).

Systems where both tags resolve to "in scope" trigger the dual-subject workflow.

### 5.2 Unified evidence retention

Both regimes mandate documentation retention:

- **NIS2:** No explicit retention period in the directive; D.Lgs 138/2024 implementing acts to specify (default 5 years for incident records per ACN guidance).
- **EU AI Act Art. 18:** Providers retain technical documentation 10 years post market placement; Art. 12 logging requirements for high-risk systems.

Default retention: **10 years** for systems in dual scope. This satisfies the longer AI Act retention requirement and over-satisfies the NIS2 retention requirement, simplifying operational policy.

### 5.3 Annual review cadence

NIS2 Art. 21.2(f) requires periodic review of cybersecurity risk management. EU AI Act Art. 9 requires continuous risk management with periodic update. ISO/IEC 42001 Clause 9.3 requires management review.

Recommended cadence for dual-subject organizations: **quarterly review** of:

- AI system inventory (additions, removals, classification changes).
- Incident log (both NIS2 and AI Act notifications, with cross-references).
- Supplier/provider documentation updates (e.g., new GPAI model version requiring Art. 53 information refresh).
- Crosswalk applicability per system (status changes can shift a system in/out of dual scope).

The platform's G-01 to G-30 checklist can support this cadence with a "last reviewed" timestamp per control, anchored to a dual-subject flag.

## 6. Scope limitations

This crosswalk addresses NIS2 and EU AI Act for **deployer-side organizations**. It does not exhaustively map:

- **Provider-side AI Act obligations** (Art. 9-15, Art. 16) — these are separate and apply to organizations placing high-risk AI systems on the market. Many essential entities will also be providers of in-house AI systems they deploy; in those cases, both deployer and provider obligations apply, and a separate provider-side crosswalk is recommended.
- **GPAI Art. 53 obligations** — the upstream provider obligations are referenced where they affect downstream deployer documentation, but not mapped exhaustively.
- **Other adjacent regimes** — DORA (financial services operational resilience), GDPR Art. 22 (automated decision-making), Colorado SB 24-205 (US-Colorado algorithmic discrimination), Polish national AI Act draft (18.11.2025). These crosswalks may be added in subsequent contributions.

The current document focuses on the highest-density overlap — NIS2 Art. 21.2 + Art. 23 with EU AI Act Art. 9-15 (referenced where deployer-relevant), Art. 26, Art. 72, Art. 73 — and the Italian-specific routing layer that D.Lgs 138/2024 introduces.

## 7. References and further reading

**EU AI Act (Regulation (EU) 2024/1689):**
- Art. 9 (risk management system)
- Art. 11 + Annex IV (technical documentation)
- Art. 12 (record-keeping)
- Art. 14 (human oversight)
- Art. 15 (accuracy, robustness, cybersecurity)
- Art. 26 (deployer obligations)
- Art. 27 (FRIA)
- Art. 53 (GPAI provider obligations)
- Art. 72 (post-market monitoring)
- Art. 73 (serious incident reporting)

**NIS2 Directive ((EU) 2022/2555):**
- Art. 21 (cybersecurity risk-management measures)
- Art. 23 (reporting obligations)
- Annex I + Annex II (essential and important entities scope)

**Italian transposition:**
- D.Lgs 138/2024 (Italian NIS2 transposition, in force 16.10.2024)
- ACN reporting portal and incident classification guidance
- Open: Italian AI Act competent authority designation (consultation in progress as of May 2026)

**Related standards (anchor for ISO 42001 users):**
- ISO/IEC 42001:2023 (AI management system)
- ISO/IEC 27001:2022 (information security management system — substantial overlap with NIS2)
- ISO/IEC 27090 (forthcoming, AI security)

---

## Maintenance note

This crosswalk was contributed under Issue #95 (accepted by @fabriziosalmi 2026-05-19). It will be updated as:

- Italian AI Act competent authority is designated.
- Final EU AI Act Article 50 guidelines are published (current consultation closes 3 June 2026).
- D.Lgs 138/2024 implementing decrees clarify retention and incident format specifics.

Contributions and corrections welcome via PR or issues.
