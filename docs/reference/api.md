# API Reference

The NIS2 Platform exposes a REST API at `http://localhost:8000`. Interactive OpenAPI documentation is available at `/docs` (Swagger UI) and `/redoc` (ReDoc).

All endpoints return JSON. Authenticated endpoints require a `Bearer` token in the `Authorization` header.

## Authentication

| Method | Path | Description | Auth |
|---|---|---|---|
| POST | `/api/auth/register` | Register a new user | No |
| POST | `/api/auth/login` | Obtain access and refresh tokens | No |
| POST | `/api/auth/refresh` | Refresh an expired access token | Yes |
| POST | `/api/auth/logout` | Invalidate the current token | Yes |
| GET | `/api/auth/me` | Get current user profile | Yes |

## Scans

| Method | Path | Description | Auth |
|---|---|---|---|
| POST | `/api/scans` | Create and queue a new scan | Yes |
| GET | `/api/scans` | List scans for current organization | Yes |
| GET | `/api/scans/{scan_id}` | Get scan details and status | Yes |
| DELETE | `/api/scans/{scan_id}` | Delete a scan and its findings | Yes |
| GET | `/api/scans/{scan_id}/findings` | List findings for a scan | Yes |
| GET | `/api/scans/compare` | Compare two scans (query params: `scan_a`, `scan_b`) | Yes |

## Findings

| Method | Path | Description | Auth |
|---|---|---|---|
| GET | `/api/findings` | List all findings (filterable by severity, status, asset, article) | Yes |
| GET | `/api/findings/{finding_id}` | Get finding details | Yes |
| PATCH | `/api/findings/{finding_id}` | Update finding status (resolved, accepted, false positive) | Yes |

## Assets

| Method | Path | Description | Auth |
|---|---|---|---|
| POST | `/api/assets` | Create a new asset | Yes |
| GET | `/api/assets` | List assets for current organization | Yes |
| GET | `/api/assets/{asset_id}` | Get asset details | Yes |
| PUT | `/api/assets/{asset_id}` | Update an asset | Yes |
| DELETE | `/api/assets/{asset_id}` | Delete an asset | Yes |

## Schedules

| Method | Path | Description | Auth |
|---|---|---|---|
| POST | `/api/schedules` | Create a scan schedule (cron expression) | Yes |
| GET | `/api/schedules` | List scan schedules | Yes |
| PUT | `/api/schedules/{schedule_id}` | Update a schedule | Yes |
| DELETE | `/api/schedules/{schedule_id}` | Delete a schedule | Yes |

## Reports

| Method | Path | Description | Auth |
|---|---|---|---|
| POST | `/api/reports` | Generate a report (PDF, JSON, or CSV) | Yes |
| GET | `/api/reports` | List generated reports | Yes |
| GET | `/api/reports/{report_id}` | Download a report file | Yes |

## Organizations

| Method | Path | Description | Auth |
|---|---|---|---|
| POST | `/api/organizations` | Create an organization | Yes |
| GET | `/api/organizations/{org_id}` | Get organization details | Yes |
| PUT | `/api/organizations/{org_id}` | Update organization settings | Yes |
| POST | `/api/organizations/{org_id}/members` | Invite a member | Yes |

## Health

| Method | Path | Description | Auth |
|---|---|---|---|
| GET | `/api/health` | Service health check (DB, Redis, Celery) | No |

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
| 422 | Unprocessable entity (invalid request body) |
| 429 | Rate limit exceeded |
| 500 | Internal server error |

## Rate Limiting

API endpoints are rate-limited per user. Default: 100 requests per minute. Rate limit headers are included in responses: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`.
