# API Reference

The NIS2 Platform exposes a REST API at `http://localhost:8000`. All routes are prefixed with `/api/v1/`. Interactive OpenAPI documentation is available at `/docs` (Swagger UI) and `/redoc` (ReDoc).

All endpoints return JSON. Two authentication paths are accepted on every protected route:

- **Cookie session (web)** — `access_token` httpOnly cookie set by `/auth/login` or `/auth/register`. State-changing requests must echo the `csrf_token` cookie back as the `X-CSRF-Token` header (double-submit pattern).
- **Bearer token (SDK / CLI)** — `Authorization: Bearer <jwt>` header. Mints from `/auth/login` are valid; the same access token from the cookie can be used here.

Read-only endpoints under **scans / findings / assets** additionally accept a long-lived **API key** as `Authorization: Bearer nis2_…` (no cookie required). Keys are minted via `POST /api/v1/api-keys` (admin only) and the raw value is shown exactly once. Mutation endpoints (POST / PATCH / DELETE) on those resources still require a session — the audit log + `created_by` columns want a user identity to attribute the change to.

## Authentication

| Method | Path | Description | Auth |
|---|---|---|---|
| POST | `/api/v1/auth/register` | Register a new user and create an organization. Returns access and refresh tokens (also set as httpOnly cookies for the web client) | No |
| POST | `/api/v1/auth/login` | Obtain access and refresh tokens | No |
| POST | `/api/v1/auth/refresh` | Rotate the access token using the refresh token cookie. Refresh tokens themselves are single-use (jti tracked in `revoked_tokens`); reusing one revokes the entire family | No |
| POST | `/api/v1/auth/logout` | Clear cookies and revoke the refresh token | Yes |
| GET | `/api/v1/auth/me` | Get current user profile | Yes |
| PATCH | `/api/v1/auth/me` | Update current user profile (name / locale / avatar). **Does not** accept `current_password` / `new_password` — see `/auth/change-password` | Yes |
| POST | `/api/v1/auth/change-password` | Rotate the user's password. Verifies `current_password`, hashes `new_password`, stamps `password_changed_at` so every other still-active session is invalidated on its next request, re-issues this session's cookies. `5/min/IP` rate-limited | Yes |
| POST | `/api/v1/auth/forgot-password` | Kick off the email-based reset flow. Always returns 204 regardless of whether the email exists, so the response can't be used to enumerate registered users. `5/min/IP` rate-limited | No |
| POST | `/api/v1/auth/reset-password` | Complete the reset flow with a single-use token (delivered out-of-band by email) and a new password. Tokens are sha256-hashed at rest, expire after `RESET_TOKEN_TTL_MINUTES` (default 30), and a single 400 covers `{unknown, expired, used}` — no oracle on which one applies. `10/min/IP` rate-limited | No |
| POST | `/api/v1/auth/switch-org` | Switch the active organization for the current session. Body: `{"organization_id": "<uuid>"}`. Validates the caller has a membership for the target org (403 otherwise — the org may exist but the membership doesn't), then mints fresh access / refresh / csrf tokens with the new `org_id` claim and rotates the cookies. Returns `TokenResponse` (same shape as `/login`). Used by the web client's org-switcher dropdown; SDKs can call it the same way. `10/min/IP` rate-limited | Yes |

## Scans

`Auth` column legend: **Session** = cookie or `Bearer <jwt>`. **API key** = `Bearer nis2_…` also accepted (no cookie required).

| Method | Path | Description | Auth |
|---|---|---|---|
| GET | `/api/v1/scans` | List scans for current organization. Filterable by `status`. Paginated | Session or API key |
| POST | `/api/v1/scans` | Create and queue a new scan | Session |
| GET | `/api/v1/scans/{scan_id}` | Get scan details and status | Session or API key |
| DELETE | `/api/v1/scans/{scan_id}` | Delete a scan and its findings (admin only) | Session |
| GET | `/api/v1/scans/{scan_id}/results` | List raw scan results for a scan. Paginated | Session or API key |
| GET | `/api/v1/scans/{scan_id}/findings` | List findings for a scan. Paginated | Session or API key |
| POST | `/api/v1/scans/{scan_id}/cancel` | Cancel a pending or running scan | Session |
| GET | `/api/v1/scans/{scan_id}/compare/{other_id}` | Compare two scans: score delta, new/resolved/persistent findings | Session or API key |

## Findings

| Method | Path | Description | Auth |
|---|---|---|---|
| GET | `/api/v1/findings` | List all findings. Filterable by `severity`, `status`, `category`. Paginated | Session or API key |
| GET | `/api/v1/findings/stats` | Get finding counts grouped by severity and status | Session or API key |
| GET | `/api/v1/findings/{finding_id}` | Get finding details | Session or API key |
| PATCH | `/api/v1/findings/{finding_id}` | Update finding status or resolution note | Session |
| POST | `/api/v1/findings/bulk-update` | Bulk update status for multiple findings | Session |

## Assets

| Method | Path | Description | Auth |
|---|---|---|---|
| GET | `/api/v1/assets` | List assets for current organization. Paginated | Session or API key |
| POST | `/api/v1/assets` | Create a new asset | Session |
| GET | `/api/v1/assets/{asset_id}` | Get asset details | Session or API key |
| PATCH | `/api/v1/assets/{asset_id}` | Update an asset | Session |
| DELETE | `/api/v1/assets/{asset_id}` | Delete an asset | Session |
| POST | `/api/v1/assets/import` | Import assets from a CSV file | Session |

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
| POST | `/api/v1/organizations` | Create a new organization owned by the current user. Body: `{"name": "<string>"}` (1..256 chars). The slug is derived server-side from the name with a numeric suffix appended on collision. The caller is automatically added as an `accepted_at`-stamped admin member. `5/min/IP` rate-limited; audit-logged as `organization.created`. Returns the new `OrgResponse` with HTTP 201 | Yes |
| GET | `/api/v1/organizations/{org_id}` | Get organization details | Yes |
| PATCH | `/api/v1/organizations/{org_id}` | Update organization settings (admin only) | Yes |
| GET | `/api/v1/organizations/{org_id}/members` | List organization members | Yes |
| POST | `/api/v1/organizations/{org_id}/members` | Invite a member by email (admin only) | Yes |
| PATCH | `/api/v1/organizations/{org_id}/members/{member_id}` | Update a member's role (admin only). Body: `{"role": "admin" \| "auditor" \| "viewer"}`. Self-demotion and last-admin demotion are refused with 400 | Yes |
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

API keys are long-lived `Bearer` tokens (`nis2_*` prefix) for CI/CD pipelines and SDK consumers. The raw value is shown **exactly once** in the create response — store it securely; only the prefix and sha256 hash are kept server-side. Keys honor `expires_at` (the route flips `is_active=False` on first expired use, so the list view stays consistent without a sweeper cron). Successful authentications stamp `last_used_at`.

Keys authenticate the **read endpoints** of scans / findings / assets (see those sections above). Mutation endpoints still require a session.

| Method | Path | Description | Auth |
|---|---|---|---|
| GET | `/api/v1/api-keys` | List API keys for the organization (admin or auditor) | Yes |
| POST | `/api/v1/api-keys` | Create a new API key (admin only). Response includes `raw_key` — shown once | Yes |
| DELETE | `/api/v1/api-keys/{key_id}` | Revoke an API key (admin only) | Yes |

## Audit Log

Every state-changing action under organizations / api-keys / auth (and increasingly elsewhere) writes a row to the audit log. Reads are paginated and filterable; retention is 90 days.

| Method | Path | Description | Auth |
|---|---|---|---|
| GET | `/api/v1/audit-logs` | List audit entries for the organization (admin or auditor). Filterable by `action`, `resource_type`, `user_id`. Paginated. Hydrates actor (user) email + name in one batch query | Yes |

## Vendors (Art. 18 Supply Chain)

| Method | Path | Description | Auth |
|---|---|---|---|
| GET | `/api/v1/vendors` | List vendors for the organization, ordered by criticality | Yes |
| POST | `/api/v1/vendors` | Register a new vendor/supplier | Yes |
| GET | `/api/v1/vendors/stats` | Supply chain risk overview: distribution by criticality, type, location | Yes |
| GET | `/api/v1/vendors/{vendor_id}` | Get vendor details | Yes |
| PATCH | `/api/v1/vendors/{vendor_id}` | Update vendor details, status, or security assessment | Yes |
| DELETE | `/api/v1/vendors/{vendor_id}` | Remove a vendor | Yes |

## Business Impact Analysis (BIA)

| Method | Path | Description | Auth |
|---|---|---|---|
| GET | `/api/v1/bia` | List business processes for the organization | Yes |
| POST | `/api/v1/bia` | Register a business process for BIA | Yes |
| GET | `/api/v1/bia/matrix` | BIA impact matrix with automatic gap detection | Yes |
| GET | `/api/v1/bia/{process_id}` | Get business process details | Yes |
| DELETE | `/api/v1/bia/{process_id}` | Remove a business process | Yes |

## ACN Export (Italy)

| Method | Path | Description | Auth |
|---|---|---|---|
| GET | `/api/v1/acn-export/art18` | Export Art. 18 vendor inventory in ACN-compatible JSON | Yes |
| GET | `/api/v1/acn-export/bia` | Export BIA data in ACN-compatible JSON | Yes |

## Compliance Deadlines

| Method | Path | Description | Auth |
|---|---|---|---|
| GET | `/api/v1/deadlines` | NIS2 compliance timeline with countdown, urgency classification, and days remaining | No |

## CSIRT Emergency (Art. 23)

| Method | Path | Description | Auth |
|---|---|---|---|
| POST | `/api/v1/csirt/emergency` | Generate Art. 23 Early Warning payload from minimal input (3 fields). Uses latest asset inventory | Yes |

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

