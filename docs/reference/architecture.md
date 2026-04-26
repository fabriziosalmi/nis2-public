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
