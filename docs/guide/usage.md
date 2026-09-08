# Usage

## Assets

Assets are the domains, IP addresses, and CIDR ranges the platform scans and monitors.

### Adding assets

1. Navigate to **Assets** in the sidebar.
2. Click **Add Asset**.
3. Fill in:
   - **Name**: a human-readable label (e.g. `Corporate website`, `Internal network`)
   - **Target type**: `domain`, `ip`, or `cidr`
   - **Target value**: the actual value (e.g. `example.com`, `10.0.0.1`, `192.168.0.0/24`)
   - **Tags** (optional): free-text labels for grouping and filtering
4. Save the asset. It is created as `unverified` and **cannot be scanned yet** —
   see below.

### Proving authority over a target

`POST /scans` refuses an unverified target with a 403. Without that gate any
account could point the scanner — port scan, zone-transfer attempt, requests for
`/.env` — at infrastructure it has no relationship with, and the operator would
answer for it.

Open the asset and use **Verify ownership**:

- **Domain** — the platform issues a DNS TXT challenge. Publish the record it
  gives you under `_nis2-challenge.<domain>` and click check; the asset becomes
  `verified`. This is evidence, the same mechanism as Let's Encrypt's DNS-01.
- **IP address or CIDR range** — no DNS can prove anything here, so an admin
  records a named, dated statement of authority instead. It is kept in the audit
  log, attributed to whoever made it. Domains cannot use this path: they have
  evidence available, and an attestation must not be the easy way around it.

Assets created before verification existed carry the `legacy` status and keep
working; they are shown as unverified everywhere else.

### Bulk import

Click **Import** on the Assets page. Upload a CSV file with columns:

```
name,target_type,target_value,tags
Corporate website,domain,example.com,web;external
Office network,cidr,10.0.0.0/8,internal
```

`tags` is optional and semicolon-separated. Rows with invalid target types or values are rejected and reported in the import summary.

---

## Running Scans

### Manual scan

1. Go to **Scans** and click **New Scan**.
2. Select one or more assets.
3. Optionally configure:
   - **Scan type**: `full` (all checks), `quick` (TLS + headers only), or `custom`
   - **Feature toggles**: enable or disable port scanning, web checks, DNS checks, WHOIS checks
   - **Concurrency**: parallel tasks (default: 20)
   - **Timeout**: seconds per check (default: 10)
4. Click **Start Scan**. The scan is queued immediately.

Scan status values:

| Status | Meaning |
|---|---|
| `pending` | Queued, waiting for a Celery worker |
| `running` | Active execution |
| `completed` | All checks finished, findings available |
| `cancelled` | Stopped by a user before completion |
| `failed` | Unrecoverable error during execution |

### Cancelling a scan

A scan in `pending` or `running` state can be cancelled from the Scans list via the **Cancel** action. The Celery task is revoked and the scan status is set to `cancelled`.

---

## Findings

The **Findings** page lists all issues discovered across all scans for the organisation.

### Filters

| Filter | Options |
|---|---|
| Severity | `critical`, `high`, `medium`, `low`, `info` |
| Status | `open`, `acknowledged`, `in_progress`, `resolved`, `accepted_risk` |
| Category | TLS, DNS, Headers, Ports, Secrets, Legal, WHOIS |

### Finding detail

Each finding includes:
- **Check name** and category
- **Severity** with CVSS rationale
- **NIS2 article** mapping (e.g. Art. 21(h) for TLS issues)
- **Description** of what was detected
- **Remediation steps** — specific, actionable guidance

### Updating finding status

Update a single finding's status from its detail page. Use **Bulk Update** on the Findings list to update multiple findings at once — useful when acknowledging a batch of findings after a review cycle.

### Finding lifecycle

Findings are generated per scan. A resolved finding from scan A is independent of the same check in scan B. Use the scan comparison feature to track remediation progress across scans over time.

---

## Compliance Matrix

The **Compliance Matrix** maps scan findings to NIS2 Art. 21 sub-paragraphs (a) through (j).

- The matrix reads from the `compliance_matrix` field of the most recent completed scan.
- Each row represents a NIS2 article; each column shows whether the article has open findings, and the count.
- Use it to produce a quick view of which articles are covered and which have outstanding issues.

For a full breakdown of which checks map to which articles, see [NIS2 Compliance Matrix](../reference/compliance-matrix.md).

---

## Reports

Reports export scan data in a format suitable for board presentations, auditor submissions, or CSIRT notifications.

### Generating a report

1. Navigate to **Reports** and click **Generate Report**.
2. Select a completed scan.
3. Choose a format:
   - **PDF**: the full NIS2 dossier, not just the scan matrix. Since v2.6.0 it carries the governance (Art. 21), incident (Art. 23), supply chain (Art. 18) and BIA sections, a score donut, an Art. 21 a-j coverage heatmap and a severity distribution. Produced as PDF/A-2b, tagged and accessible, with an embedded font, and localised into all supported languages
   - **JSON**: machine-readable, includes full finding detail
   - **CSV**: tabular findings export for spreadsheet analysis
   - **HTML**: self-contained page for archiving
   - **JUnit XML**: for integration with CI/CD pipelines
4. Report generation runs asynchronously as a Celery task.
5. Poll the status on the Reports page; download when the report shows as ready.

Reports are stored on the `reports-data` Docker volume and cleaned up automatically after `REPORT_TTL_DAYS` days (default: 30).

---

## Scheduled Scans

Automate recurring scans with cron-based schedules.

### Creating a schedule

1. Go to **Schedules** and click **New Schedule**.
2. Select target assets.
3. Set a cron expression:
   - `0 2 * * 1` — every Monday at 02:00
   - `0 3 * * *` — daily at 03:00
   - `0 0 1 * *` — first day of each month
4. Configure scan parameters (same options as manual scans).
5. Save the schedule. Celery Beat picks it up and dispatches scans at the specified cadence.

### Running a schedule immediately

Use the **Run Now** action on any schedule to trigger it outside its regular cadence. This creates a normal scan run and does not affect the next scheduled execution.

---

## Scan Comparison

Compare two completed scans to track remediation progress.

1. From the **Scans** page, select any two completed scans within the organisation.
2. The comparison view shows:
   - **New findings**: present in the scan you opened, absent from the one you
     compared it against — so, comparing a recent scan against an older one,
     what has appeared since.
   - **Resolved findings**: present in the scan you compared against, absent
     from the one you opened — the check now passes.
   - **Persistent findings**: present in both scans (unresolved).
   - **Score delta**: the numerical difference in total compliance score.

Direction matters: the endpoint is `GET /api/v1/scans/{scan_id}/compare/{other_id}`,
and "new" means *in `scan_id`, not in `other_id`*. Open the newer scan and
compare it against the older one, or the two columns read backwards.

Use scan comparison to demonstrate remediation progress in audit reports.

---

## Governance

The **Governance** section covers organisational and non-technical NIS2 requirements that the scanner cannot evaluate.

### Checklist

The 30-item checklist cross-references NIS2 Art. 21 sub-paragraphs. Each item has:
- A status (`pending`, `in_progress`, `compliant`, `not_applicable`)
- An owner (free text — e.g. `IT Manager`, `Legal`, `CISO`)
- An evidence field (document reference or URL)

Work through the checklist alongside technical scanning. Most items require human verification, policy documents, or board decisions. See [Governance Checklist](../governance/checklist.md) for the full item list.

### Risk Register

The risk register integrates with scanner findings. Triggering `POST /api/v1/governance/sync-risk` escalates checklist items when open `high` or `critical` severity findings are associated with that article. This bridges the gap between technical posture and governance documentation.

`GET /api/v1/governance/risk-summary` returns a structured view of open risks by NIS2 article.

---

## Incident Management (Art. 23)

Track incidents from detection through the CSIRT reporting lifecycle.

### Incident lifecycle

| Phase | Legal deadline | Platform support |
|---|---|---|
| Early Warning | 24 hours | Generates a CSIRT-ready Early Warning JSON; Celery Beat alerts at breach and 2 h before |
| Incident Notification | 72 hours | Structured notification form with taxonomy, IOCs, timeline; same alerting |
| Final Report | 1 month | Aggregated impact assessment and lessons learned; same alerting |

Alerts are dispatched through configured notification channels (email, webhook, Slack). Deduplication is Redis-backed — the same alert is not sent twice for the same incident and deadline.

**Submission to CSIRT Italia** (`csirt.gov.it`) is a manual step. The platform produces the artefacts and tracks deadlines; it does not push directly to the CSIRT portal.

---

## Vendor Risk Management (Art. 18)

Track third-party vendors and assess their security posture.

### Adding a vendor

Navigate to **Vendors** and click **Add Vendor**. Required fields:
- **Name** and **criticality** (1 = low, 4 = critical)
- **Data access level**: none / pseudonymised / personal / sensitive
- **Geographic location** of data processing

Optional fields that affect the scoring formula:
- ISO 27001, SOC2, CSA STAR certifications
- Audit recency
- Security clauses and SLA in contract
- ACN Art. 18 relevance flag (Italy)

### Vendor score

Each vendor receives a 0–100 security score computed from a documented formula. The formula and its weights are publicly accessible at `GET /api/v1/vendors/score-formula` — auditors can verify the calculation independently.

---

## Dashboard pages

Since v2.6.0 the capabilities that were API-only have a full interface. The sidebar covers:

| Page | Route | What it shows |
|---|---|---|
| Incidents | `/dashboard/incidents` | The Art. 23 deadline monitor, with live countdowns to the 24 hour, 72 hour and 1 month obligations |
| Governance | `/dashboard/governance` | The 30-item Art. 21 checklist, the weighted score, and a button that runs the scanner-to-compliance bridge live |
| Suppliers | `/dashboard/vendors` | Art. 18 supply chain risk: criticality, data access, security score |
| Business Impact | `/dashboard/bia` | The continuity table: RTO, RPO, MTPD, BCP and DRP per process |

All of them are localised across the five supported locales.

---

## Business Impact Analysis

The BIA page records, per business process, the recovery objectives that NIS2 expects you to have thought about: **RTO** (how long you can be down), **RPO** (how much data you can afford to lose), and **MTPD** (the point past which the damage is no longer recoverable), along with whether a business continuity plan and a disaster recovery plan exist.

The value is not the table itself, it is the gaps it makes visible: a process with a two hour RTO and no DRP is a documented contradiction, which is exactly what an auditor asks about.

---

## Team Management

Manage organisation members under **Settings > Team**.

### Roles

| Role | Permissions |
|---|---|
| `admin` | Full access, manage members and settings, generate API keys |
| `auditor` | Run scans, view all data, generate reports, manage schedules |
| `viewer` | Read-only access to scans, findings, and reports |

### Inviting members

Click **Invite Member**, enter the email address, and select a role. The invitation is sent by email (or captured by the dev outbox in development). The invitee registers or signs in and is added to the organisation.

### Multiple organisations

A user can belong to multiple organisations with different roles in each. Use the organisation switcher in the top navigation bar to change the active organisation. Switching calls `POST /api/v1/auth/switch-org` and mints fresh tokens scoped to the new organisation.

---

## API Keys

API keys provide long-lived programmatic access to the REST API without requiring cookie-based session authentication.

### Creating an API key

1. Navigate to **Settings > API Keys**.
2. Click **Create API Key**, give it a name, and select scopes:
   - `scan:read`, `scan:write`
   - `finding:read`
   - `asset:read`
   - `report:read`
3. The raw key value is shown exactly once on creation. Copy it immediately.

API keys are stored as bcrypt hashes. The raw value cannot be retrieved after creation.

### Using an API key

Pass the key as a Bearer token:

```bash
curl -H "Authorization: Bearer nis2_<key>" \
  https://nis2.example.com/api/v1/findings
```

API keys are accepted on read endpoints for scans, findings, and assets. Mutation endpoints (POST, PATCH, DELETE) require a session — the audit log requires a user identity.

### Revoking an API key

Delete a key from **Settings > API Keys**. Deletion is immediate — in-flight requests using the revoked key will receive `401`.

---

## TOTP Multi-Factor Authentication

The platform supports TOTP-based MFA (RFC 6238) for user accounts. MFA is opt-in per user and satisfies NIS2 Art. 21(j) on authentication controls.

### Enabling TOTP

1. Go to **Settings > Security**.
2. Click **Enable Two-Factor Authentication**.
3. Scan the QR code with an authenticator app (Google Authenticator, Authy, etc.).
4. Enter a code from the app to confirm the setup.

Once enabled, login requires both the password and a valid TOTP code.

### Disabling TOTP

From **Settings > Security**, click **Disable Two-Factor Authentication** and enter a current TOTP code to confirm.
