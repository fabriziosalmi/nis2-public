# Architecture

## Overview

The NIS2 Platform is a monorepo containing three packages, orchestrated by Docker Compose.

```
User (Browser)
  |
  v
Caddy (reverse proxy, auto-HTTPS)
  |
  +---> Next.js 15 (frontend, port 8077)
  |
  +---> FastAPI (API, port 8000)
          |
          +---> PostgreSQL (persistent storage)
          +---> Redis (cache, sessions, Celery broker)
          +---> Celery Worker (scan execution, report generation)
          +---> Celery Beat (scheduled scan dispatch)
                  |
                  v
              Scanner (Python, aiohttp + asyncio)
```

## Monorepo Structure

| Path | Technology | Purpose |
|---|---|---|
| `packages/scanner` | Python (aiohttp, asyncio, dnspython, playwright) | Scanner with NIS2 compliance checks |
| `packages/api` | FastAPI (Python) | REST API, authentication, Celery task definitions |
| `packages/web` | Next.js 15, shadcn/ui | Frontend dashboard |
| `infra/docker` | Docker Compose | Dev and production orchestration, Caddy config |
| `scripts/` | Python | Database seeding, migration helpers |
| `docs/` | VitePress | This documentation |

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 15, React, shadcn/ui, Tailwind CSS |
| API | FastAPI, Pydantic, SQLAlchemy (async), Alembic |
| Task Queue | Celery, Celery Beat, Redis (broker + backend) |
| Database | PostgreSQL |
| Cache/Sessions | Redis |
| Scanner | Python, aiohttp, asyncio, dnspython, playwright |
| Reverse Proxy | Caddy (auto-HTTPS via Let's Encrypt) |
| Auth | JWT (access + refresh tokens), NextAuth |

## Data Flow

### Scan Execution

1. User creates a scan via the dashboard or API (`POST /api/v1/scans`).
2. The API validates the request, creates a scan record in PostgreSQL, and dispatches a Celery task.
3. The Celery worker picks up the task and invokes the scanner against each target asset.
4. The scanner executes checks in parallel using `asyncio`. HTTP requests use `aiohttp`. DNS lookups use `dnspython`. Legal page analysis uses `playwright` for browser rendering.
5. Results pass through the compliance engine, which maps findings to NIS2 articles and calculates severity.
6. Findings are written to PostgreSQL. The scan's `compliance_matrix` field is populated.
7. The scan status is updated to "completed."
8. The frontend polls the API and displays results when ready.

### Scheduled Scans

1. An admin or auditor creates a schedule with a cron expression via the dashboard or API.
2. Celery Beat evaluates cron expressions and dispatches scan tasks at the configured times.
3. Execution follows the same flow as manual scans.

### Report Generation

1. User requests a report via the dashboard or API (`POST /api/v1/reports/generate`).
2. A Celery task generates the report in the requested format (PDF, JSON, CSV).
3. The task result (including the file path) is stored in Redis as a Celery task result. There is no `reports` database table.
4. The user polls status via `GET /api/v1/reports/status/{task_id}` and downloads via `GET /api/v1/reports/download/{task_id}`.

### Art. 23 deadline alerts

1. Celery Beat runs a deadline check task every 15 minutes.
2. For each open incident, it computes the time remaining until the 24 h, 72 h, and 1-month CSIRT thresholds.
3. When a threshold is within 2 hours or has just passed, an alert is dispatched to all configured notification channels (email, webhook, Slack).
4. A Redis key prevents duplicate alerts for the same incident and threshold within a deduplification window.

## Database Schema (Tables)

| Table | Description |
|---|---|
| `users` | User accounts (email, hashed password, full name, active flag) |
| `organizations` | Tenant organizations (name, slug) |
| `memberships` | User-organization membership with role (admin, auditor, viewer) |
| `assets` | Scan targets (name, target type, target value, tags) |
| `scans` | Scan runs (status, config snapshot, timestamps, compliance matrix, scores) |
| `scan_results` | Raw scan result data per target per scan |
| `findings` | Individual check results (severity, NIS2 article, category, status, remediation) |
| `scan_schedules` | Cron-based scan schedules (cron expression, config, active flag) |
| `api_keys` | User-generated API keys for programmatic access |
| `notification_channels` | Notification channel configuration per organization |
| `audit_logs` | Audit trail of user actions |

## Multi-Tenancy Model

Data isolation is enforced at the organization level:

- Every asset, scan, finding, and schedule belongs to an organization.
- API queries are automatically scoped to the user's current organization.
- Users can belong to multiple organizations with different roles.
- Role-based access control (RBAC) restricts actions:
  - **Admin**: full access, manage members and settings.
  - **Auditor**: run scans, view all data, generate reports, manage schedules.
  - **Viewer**: read-only access.

### How isolation is enforced

Every user-facing table except `users`, `organizations`, `memberships`, and auth-related tables carries an `organization_id` column. PostgreSQL Row-Level Security (RLS) enforces isolation at the database layer:

- Migration `002_add_rls_policies` enables RLS and creates a `tenant_isolation` policy on all tenant-scoped tables.
- Every request sets `app.current_org_id` as a PostgreSQL session-local variable before executing queries.
- The RLS policy predicate: `organization_id::text = current_setting('app.current_org_id', true) OR current_setting('app.bypass_rls', true) = 'on'`
- The `app.bypass_rls = 'on'` path is used only for bootstrap operations (user creation, org creation) within the same transaction, then cleared automatically when the transaction ends.

The application database role must be `NOSUPERUSER NOBYPASSRLS`. Superuser roles bypass RLS unconditionally even when `FORCE ROW LEVEL SECURITY` is set. If the application connects as a superuser, the API logs a warning and in `ENVIRONMENT=production` refuses to start.

## Authentication Model

### Session-based (web)

1. `POST /auth/login` sets three httpOnly cookies: `access_token`, `refresh_token`, `csrf_token`.
2. State-changing requests must echo `csrf_token` as the `X-CSRF-Token` header (double-submit CSRF protection).
3. `POST /auth/refresh` issues a new access token and rotates the refresh token. Refresh tokens are single-use; reusing a spent token revokes the entire token family (jti chain tracking in `revoked_tokens`).

### Bearer token (API / SDK)

The JWT from any login response can also be passed as `Authorization: Bearer <token>`. No cookie is required.

### API key

Long-lived keys prefixed `nis2_` are accepted on read endpoints without a cookie. Keys carry explicit scopes (`finding:read`, `asset:read`, `scan:read`, etc.) and are validated against the endpoint's required scope on every request.

### TOTP MFA

After password validation, if the user has TOTP enabled, the login flow requires an additional `POST /auth/totp/verify` with a valid 6-digit TOTP code before issuing tokens. TOTP secrets are stored encrypted in the `users` table.

### RS256 support

When `JWT_ALGORITHM=RS256`, tokens are signed with the RSA private key and can be verified by third-party systems using the public key published at `GET /.well-known/jwks.json` in standard JWKS format.


## Security Controls Summary

| Control | Implementation |
|---|---|
| Tenant isolation | PostgreSQL RLS (`tenant_isolation` policy, `FORCE ROW LEVEL SECURITY`) |
| Authentication | JWT (HS256 or RS256), httpOnly cookies, CSRF double-submit |
| Multi-factor authentication | TOTP (RFC 6238) per user |
| Session integrity | Refresh token rotation with family revocation |
| Password security | bcrypt hashing, `password_changed_at` watermark for cross-session invalidation |
| Rate limiting | SlowAPI on all auth and sensitive endpoints |
| Audit trail | Per-request `audit_logs` with action, resource, IP, and user agent |
| Content security | Content-Security-Policy, X-Frame-Options, HSTS (via Caddy) |
| API key scopes | Endpoint-level scope enforcement via `dual_auth_with_scope()` |
| Secret detection | gitleaks on full git history in CI |
| Dependency audit | pip-audit (Python) and npm audit (Node.js) in CI |
