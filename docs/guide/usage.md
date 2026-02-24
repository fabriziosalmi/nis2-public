# Usage

## Running a Scan
Execute the scanner module with your configuration files:

```bash
python -m nis2_checker.main --config config.yaml --targets targets.yaml
```

## Authentication
To scan protected targets, define `auth_id` in `targets.yaml` and set corresponding environment variables:

- **Bearer Token**: `export INTERNAL_API_TOKEN="your-token"`
- **Basic Auth**: 
  ```bash
  export INTERNAL_API_USER="username"
  export INTERNAL_API_PASS="password"
  ```

## View Reports
After a scan, reports are generated:
- Console output shows a summary.
- `nis2_report.json`: Detailed machine-readable results.
- `nis2_report.html`: Visual dashboard.
- `report.pdf`: Professional PDF report for management.

## CI/CD Integration

### GitHub Actions
The `.github/workflows/nis2.yml` workflow is configured for **manual trigger only** (`workflow_dispatch`). Add repository secrets for any authenticated scan targets.

> [!WARNING]
> Do not run Nmap scans from public GitHub runners — it violates GitHub's Acceptable Use Policy. Use Self-Hosted Runners or connect through a VPN to scan internal infrastructure.

### GitLab CI
The `.gitlab-ci.yml` pipeline runs on schedules. Configure CI/CD variables for secrets.
