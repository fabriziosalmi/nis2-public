# Usage

## Assets

Assets represent the domains, IPs, or CIDR ranges you want to scan.

1. Navigate to **Assets** in the sidebar.
2. Click **Add Asset** and enter a domain (e.g., `example.com`), IP address, or CIDR range.
3. Each asset has a name, target type (domain, ip, cidr), target value, and optional tags.

You can also bulk-import assets from a CSV file via the **Import** button. Expected columns: `name`, `target_type`, `target_value`, `tags` (optional, semicolon-separated).

Assets belong to your organization and are visible to all members based on their role.

## Running Scans

1. Go to **Scans** and click **New Scan**.
2. Select one or more assets to scan.
3. Optionally configure scan type (full, quick, custom), feature toggles (port scan, web checks, DNS checks, WHOIS checks), concurrency, and timeout.
4. Click **Start Scan**. The scan is queued as a Celery task and runs asynchronously.
5. The scan status updates as the frontend polls: pending, running, completed, cancelled, or failed.

## Viewing Findings

The **Findings** page lists all issues discovered across scans.

- Filter by severity (critical, high, medium, low, info), status, or category.
- Each finding includes: check name, severity, NIS2 article mapping, description, and remediation steps.
- Finding statuses: **open**, **acknowledged**, **in_progress**, **resolved**, **accepted_risk**.
- Update a single finding's status, or use bulk update to change multiple findings at once.

## Compliance Matrix

The **Compliance Matrix** maps findings to NIS2 Art. 21 requirements.

- The matrix reads from the `compliance_matrix` field of the most recent completed scan.
- Rows represent NIS2 articles; columns show compliance status.
- Use it to see which articles have associated findings and which are clear.

## Reports

Generate exportable reports from scan results.

1. Navigate to **Reports** and click **Generate Report**.
2. Select a completed scan and a format (PDF, JSON, or CSV).
3. Report generation runs asynchronously via Celery. Poll the status or wait for it to appear as ready, then download.

## Scheduled Scans

Automate recurring scans with cron-based scheduling.

1. Go to **Schedules** and click **New Schedule**.
2. Select assets, set a cron expression (e.g., `0 2 * * 1` for every Monday at 2 AM).
3. Celery Beat dispatches scans on schedule.
4. You can also trigger a scheduled scan immediately via the **Run Now** action.

## Scan Comparison

Compare two scans to track remediation progress.

1. From the **Scans** page, select any two completed scans in the organization.
2. The comparison view shows:
   - **New findings**: issues present in the first scan but not the second.
   - **Resolved findings**: issues present in the second scan but not the first.
   - **Persistent findings**: issues present in both scans.
   - **Score delta**: the difference in total score between the two scans.

## Team Management

Manage organization members under **Settings > Team**.

- **Invite members** by email. They receive an invitation to join your organization.
- **Assign roles**:
  - **Admin**: full access, manage members and settings.
  - **Auditor**: run scans, view all data, generate reports.
  - **Viewer**: read-only access to scans, findings, and reports.
- **Update roles** or **remove members** as needed.

## API Keys

Generate API keys under **Settings > API Keys** for programmatic access to the REST API. Keys inherit the permissions of the user who created them. See the [API Reference](../reference/api.md) for endpoint documentation.
