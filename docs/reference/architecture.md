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
              Scanner (Python CLI, 50+ checks)
```

## Monorepo Structure

| Path | Technology | Purpose |
|---|---|---|
| `packages/scanner` | Python | CLI scanner with 50+ NIS2 compliance checks |
| `packages/api` | FastAPI (Python) | REST API, authentication, Celery task definitions |
| `packages/web` | Next.js 15, shadcn/ui | Frontend dashboard (16 pages) |
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
| Scanner | Python, httpx, asyncio, nmap |
| Reverse Proxy | Caddy (auto-HTTPS via Let's Encrypt) |
| Monitoring | Prometheus |
| Auth | JWT (access + refresh tokens), NextAuth |

## Data Flow

### Scan Execution

1. User creates a scan via the dashboard or API (`POST /api/scans`).
2. The API validates the request, creates a scan record in PostgreSQL, and dispatches a Celery task.
3. The Celery worker picks up the task and invokes the scanner against each target asset.
4. The scanner executes 50+ checks in parallel using `asyncio` and `httpx`.
5. Results pass through the compliance engine, which maps findings to NIS2 articles and calculates severity.
6. Findings are written to PostgreSQL.
7. The scan status is updated to "completed."
8. The frontend polls or receives the update and displays results.

### Scheduled Scans

1. An admin creates a schedule with a cron expression via the dashboard or API.
2. Celery Beat evaluates cron expressions and dispatches scan tasks at the configured times.
3. Execution follows the same flow as manual scans.

### Report Generation

1. User requests a report via the dashboard or API (`POST /api/reports`).
2. A Celery task generates the report in the requested format (PDF, JSON, CSV).
3. The generated file is stored and made available for download.

## Database Schema (Key Tables)

| Table | Description |
|---|---|
| `users` | User accounts (email, hashed password, role) |
| `organizations` | Tenant organizations |
| `org_members` | User-organization membership with role (admin, auditor, viewer) |
| `assets` | Scan targets (domain, IP, metadata) |
| `scans` | Scan runs (status, timestamps, asset references) |
| `findings` | Individual check results (severity, NIS2 article, status, remediation) |
| `schedules` | Cron-based scan schedules |
| `reports` | Generated report metadata and file references |
| `api_keys` | User-generated API keys for programmatic access |

## Multi-Tenancy Model

Data isolation is enforced at the organization level:

- Every asset, scan, finding, schedule, and report belongs to an organization.
- API queries are automatically scoped to the user's current organization.
- Users can belong to multiple organizations with different roles.
- Role-based access control (RBAC) restricts actions:
  - **Admin**: full access, manage members and settings.
  - **Auditor**: run scans, view all data, generate reports.
  - **Viewer**: read-only access.

## Dashboard Pages

The Next.js frontend provides 16 pages:

1. Login / Register
2. Dashboard (overview, recent scans, compliance summary)
3. Assets (list, create, edit, delete)
4. Scans (list, create, details)
5. Scan Detail (findings, compliance breakdown)
6. Scan Comparison (diff between two scans)
7. Findings (filterable list across all scans)
8. Finding Detail (description, remediation, history)
9. Compliance Matrix (NIS2 Art. 21 mapping)
10. Reports (list, generate, download)
11. Schedules (list, create, edit, delete)
12. Settings (organization, profile)
13. Team Management (invite, roles, remove)
14. API Keys (generate, revoke)
15. Notifications
16. User Profile
