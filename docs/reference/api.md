# API Reference

The NIS2 Platform exposes a REST API at `http://localhost:8000`. All routes are prefixed with `/api/v1/`. Interactive OpenAPI documentation is available at `/docs` (Swagger UI) and `/redoc` (ReDoc).

All endpoints return JSON. Authenticated endpoints require a `Bearer` token in the `Authorization` header.

## Authentication

| Method | Path | Description | Auth |
|---|---|---|---|
| POST | `/api/v1/auth/register` | Register a new user and create an organization. Returns access and refresh tokens | No |
| POST | `/api/v1/auth/login` | Obtain access and refresh tokens | No |
| POST | `/api/v1/auth/refresh` | Refresh an expired access token using a refresh token | No |
| GET | `/api/v1/auth/me` | Get current user profile | Yes |
| PATCH | `/api/v1/auth/me` | Update current user profile | Yes |

## Scans

| Method | Path | Description | Auth |
|---|---|---|---|
| GET | `/api/v1/scans` | List scans for current organization. Filterable by `status`. Paginated | Yes |
| POST | `/api/v1/scans` | Create and queue a new scan | Yes |
| GET | `/api/v1/scans/{scan_id}` | Get scan details and status | Yes |
| DELETE | `/api/v1/scans/{scan_id}` | Delete a scan and its findings (admin only) | Yes |
| GET | `/api/v1/scans/{scan_id}/results` | List raw scan results for a scan. Paginated | Yes |
| GET | `/api/v1/scans/{scan_id}/findings` | List findings for a scan. Paginated | Yes |
| POST | `/api/v1/scans/{scan_id}/cancel` | Cancel a pending or running scan | Yes |
| GET | `/api/v1/scans/{scan_id}/compare/{other_id}` | Compare two scans: score delta, new/resolved/persistent findings | Yes |

## Findings

| Method | Path | Description | Auth |
|---|---|---|---|
| GET | `/api/v1/findings` | List all findings. Filterable by `severity`, `status`, `category`. Paginated | Yes |
| GET | `/api/v1/findings/stats` | Get finding counts grouped by severity and status | Yes |
| GET | `/api/v1/findings/{finding_id}` | Get finding details | Yes |
| PATCH | `/api/v1/findings/{finding_id}` | Update finding status or resolution note | Yes |
| POST | `/api/v1/findings/bulk-update` | Bulk update status for multiple findings | Yes |

## Assets

| Method | Path | Description | Auth |
|---|---|---|---|
| GET | `/api/v1/assets` | List assets for current organization. Paginated | Yes |
| POST | `/api/v1/assets` | Create a new asset | Yes |
| GET | `/api/v1/assets/{asset_id}` | Get asset details | Yes |
| PATCH | `/api/v1/assets/{asset_id}` | Update an asset | Yes |
| DELETE | `/api/v1/assets/{asset_id}` | Delete an asset | Yes |
| POST | `/api/v1/assets/import` | Import assets from a CSV file | Yes |

## Schedules

| Method | Path | Description | Auth |
|---|---|---|---|
| GET | `/api/v1/schedules` | List scan schedules | Yes |
| POST | `/api/v1/schedules` | Create a scan schedule (cron expression). Admin or auditor only | Yes |
| PATCH | `/api/v1/schedules/{schedule_id}` | Update a schedule | Yes |
| DELETE | `/api/v1/schedules/{schedule_id}` | Delete a schedule | Yes |
| POST | `/api/v1/schedules/{schedule_id}/run` | Trigger an immediate run of a scheduled scan | Yes |

## Reports

| Method | Path | Description | Auth |
|---|---|---|---|
| POST | `/api/v1/reports/generate` | Queue report generation for a completed scan. Params: `scan_id`, `format` (pdf, json, csv). Returns a `task_id` | Yes |
| GET | `/api/v1/reports/status/{task_id}` | Check report generation status by Celery task ID | Yes |
| GET | `/api/v1/reports/download/{task_id}` | Download a generated report file by Celery task ID | Yes |

## Organizations

| Method | Path | Description | Auth |
|---|---|---|---|
| GET | `/api/v1/organizations` | List organizations the current user belongs to | Yes |
| GET | `/api/v1/organizations/{org_id}` | Get organization details | Yes |
| PATCH | `/api/v1/organizations/{org_id}` | Update organization settings (admin only) | Yes |
| GET | `/api/v1/organizations/{org_id}/members` | List organization members | Yes |
| POST | `/api/v1/organizations/{org_id}/members` | Invite a member by email (admin only) | Yes |
| PATCH | `/api/v1/organizations/{org_id}/members/{member_id}` | Update a member's role (admin only). Query param: `role` (admin, auditor, viewer) | Yes |
| DELETE | `/api/v1/organizations/{org_id}/members/{member_id}` | Remove a member (admin only). Cannot remove the last admin | Yes |

## Health

| Method | Path | Description | Auth |
|---|---|---|---|
| GET | `/api/v1/health` | Liveness check. Returns `{"status": "ok"}` | No |
| GET | `/api/v1/health/ready` | Readiness check. Tests database and Redis connectivity | No |

## Certificates

| Method | Path | Description | Auth |
|---|---|---|---|
| POST | `/api/v1/certificates/check` | Deep certificate analysis for a single domain. Returns chain, OCSP, CT logs, key strength, 0-100 score | Yes |
| POST | `/api/v1/certificates/bulk-check` | Analyze up to 50 domains at once with summary statistics | Yes |
| GET | `/api/v1/certificates/ct-logs/{domain}` | Query Certificate Transparency logs via crt.sh | Yes |

## Remediation

| Method | Path | Description | Auth |
|---|---|---|---|
| GET | `/api/v1/remediation/playbooks` | List all available remediation playbooks | No |
| GET | `/api/v1/remediation/playbooks/{id}` | Get full playbook with steps, configs, and effort estimate | No |
| GET | `/api/v1/remediation/for-finding/{finding_id}` | Auto-match the best playbook for a specific finding | Yes |
| GET | `/api/v1/remediation/estimate/{scan_id}` | Calculate total remediation effort and cost for a scan | Yes |
| POST | `/api/v1/remediation/explain/{finding_id}` | AI-powered finding explanation with personalized remediation. Tries local LLM, then OpenAI, then playbook fallback | Yes |

## Incidents

| Method | Path | Description | Auth |
|---|---|---|---|
| POST | `/api/v1/incidents` | Report an incident (CSIRT Art. 23 taxonomy) | Yes |
| GET | `/api/v1/incidents` | List incidents for the organization | Yes |
| GET | `/api/v1/incidents/{id}` | Get incident details | Yes |
| PATCH | `/api/v1/incidents/{id}` | Update incident status or details | Yes |

## Governance

| Method | Path | Description | Auth |
|---|---|---|---|
| GET | `/api/v1/governance/checklist` | Get the 30-item NIS2 governance checklist with statuses | Yes |
| PATCH | `/api/v1/governance/checklist/{item_id}` | Update checklist item status | Yes |
| POST | `/api/v1/governance/seed` | Seed checklist from governance template | Yes |
| GET | `/api/v1/governance/score` | Get weighted compliance score | Yes |

## API Keys

| Method | Path | Description | Auth |
|---|---|---|---|
| GET | `/api/v1/api-keys` | List API keys for the organization | Yes |
| POST | `/api/v1/api-keys` | Create a new API key (admin only) | Yes |
| DELETE | `/api/v1/api-keys/{key_id}` | Revoke an API key (admin only) | Yes |

## MCP (Model Context Protocol)

| Method | Path | Description | Auth |
|---|---|---|---|
| GET | `/api/v1/mcp/tools` | List available MCP tools | No |
| POST | `/api/v1/mcp/call` | Execute an MCP tool call via HTTP | No |

## Error Responses

All errors follow a consistent format:

```json
{
  "detail": "Description of the error"
}
```

Common HTTP status codes:

| Code | Meaning |
|---|---|
| 400 | Bad request (validation error) |
| 401 | Unauthorized (missing or invalid token) |
| 403 | Forbidden (insufficient role permissions) |
| 404 | Resource not found |
| 409 | Conflict (duplicate resource) |
| 422 | Unprocessable entity (invalid request body) |
| 429 | Too many requests (rate limited) |
| 500 | Internal server error |

