# Usage

## Assets

Assets represent the domains, IPs, or services you want to scan.

1. Navigate to **Assets** in the sidebar.
2. Click **Add Asset** and enter a domain (e.g., `example.com`) or IP address.
3. Assign a label and optional tags for organization.

Assets belong to your organization and are visible to all members based on their role.

## Running Scans

1. Go to **Scans** and click **New Scan**.
2. Select one or more assets to scan.
3. Click **Start Scan**. The scan is queued as a Celery task and runs asynchronously.
4. The scan status updates in real time: queued, running, completed, or failed.

Each scan executes 50+ checks against the selected assets and produces findings mapped to NIS2 articles.

## Viewing Findings

The **Findings** page lists all issues discovered across scans.

- Filter by severity (critical, high, medium, low, info), status, asset, or NIS2 article.
- Each finding includes: check name, severity, NIS2 article mapping, description, and remediation steps.
- Mark findings as resolved, accepted risk, or false positive.

## Compliance Matrix

The **Compliance Matrix** maps findings to NIS2 Art. 21 requirements.

- Rows represent NIS2 articles; columns show compliance status.
- Drill into any article to see associated findings.
- Track compliance posture changes over time.

## Reports

Generate exportable reports from scan results.

1. Navigate to **Reports** and click **Generate Report**.
2. Select the scan(s), format (PDF, JSON, or CSV), and scope.
3. Report generation runs asynchronously via Celery. Download when ready.

Reports include: executive summary, findings by severity, compliance matrix snapshot, and remediation priorities.

## Scheduled Scans

Automate recurring scans with cron-based scheduling.

1. Go to **Schedules** and click **New Schedule**.
2. Select assets, set a cron expression (e.g., `0 2 * * 1` for every Monday at 2 AM).
3. Celery Beat dispatches scans on schedule.

Scheduled scans appear in the Scans list with a "scheduled" label.

## Scan Comparison

Compare two scan runs to track remediation progress.

1. From the **Scans** page, select two completed scans of the same asset.
2. Click **Compare**. The comparison view shows:
   - **New findings**: issues that appeared in the later scan.
   - **Resolved findings**: issues present in the earlier scan but absent in the later one.
   - **Persistent findings**: issues present in both scans.

## Team Management

Manage organization members under **Settings > Team**.

- **Invite members** by email. They receive an invitation to join your organization.
- **Assign roles**:
  - **Admin**: full access, manage members and settings.
  - **Auditor**: view and run scans, generate reports.
  - **Viewer**: read-only access to scans, findings, and reports.
- **Remove members** or change roles as needed.

## API Keys

Generate API keys under **Settings > API Keys** for programmatic access to the REST API. Keys inherit the permissions of the user who created them. See the [API Reference](../reference/api.md) for endpoint documentation.
