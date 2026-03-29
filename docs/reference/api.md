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
| 500 | Internal server error |
