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

## CI/CD Integration

### GitHub Actions
The `.github/workflows/nis2.yml` workflow runs daily. Add secrets to your repository settings to support authenticated scans.

### GitLab CI
The `.gitlab-ci.yml` pipeline runs on schedules. Configure CI/CD variables for secrets.
