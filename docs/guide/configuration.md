# Configuration

All configuration is managed through environment variables defined in `.env`. Copy `.env.example` to `.env` and adjust values for your environment.

## Database

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://nis2:nis2secret@postgres:5432/nis2` | Async database connection string (used by FastAPI) |
| `DATABASE_URL_SYNC` | `postgresql://nis2:nis2secret@postgres:5432/nis2` | Sync connection string (used by Alembic migrations) |
| `POSTGRES_USER` | `nis2` | PostgreSQL user |
| `POSTGRES_PASSWORD` | `nis2secret` | PostgreSQL password |
| `POSTGRES_DB` | `nis2` | PostgreSQL database name |
| `MIGRATION_DATABASE_URL` | (falls back to `DATABASE_URL`) | Privileged identity used ONLY for Alembic and the boot-time RLS setup. `DATABASE_URL` must point at a NOSUPERUSER NOBYPASSRLS role or every RLS policy is decorative — the API asserts this at startup and refuses to serve otherwise |
| `MIGRATION_DATABASE_URL_SYNC` | (falls back to `DATABASE_URL_SYNC`) | Sync variant of the above |
| `NIS2_APP_PASSWORD` | — | Password for the `nis2_app` runtime role, created on first volume init by `infra/docker/initdb/01-create-app-role.sh` |
| `DB_POOL_SIZE` | `10` | Connections per pool, **per gunicorn worker** — gunicorn preforks, so each worker builds its own |
| `DB_MAX_OVERFLOW` | `5` | Overflow per worker. Total demand is `workers × (pool + overflow)`; keep it below the server's `max_connections` (100 in the stock image) |

## Redis

| Variable | Default | Description |
|---|---|---|
| `REDIS_URL` | `redis://redis:6379/0` | Redis connection for caching and sessions |

## Authentication (JWT)

| Variable | Default | Description |
|---|---|---|
| `JWT_SECRET` | (change in production) | Secret key for signing JWT tokens. Generate with `openssl rand -hex 32` |
| `JWT_ALGORITHM` | `HS256` | JWT signing algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | Access token lifetime in minutes |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token lifetime in days |

## Encryption at rest

| Variable | Default | Description |
|---|---|---|
| `DATA_ENCRYPTION_KEY` | — | AES-GCM key for TOTP seeds, notification-channel credentials and leaked-secret evidence. At least 32 characters; the API refuses to boot without strong key material |
| `DATA_ENCRYPTION_KEY_PREVIOUS` | (empty) | The key being rotated away from. Set during a rotation only — see [Secrets rotation](secrets-rotation.md); decryption tries the current key first and falls back to this one |

## Observability

| Variable | Default | Description |
|---|---|---|
| `LOG_LEVEL` | `INFO` | Verbosity for the API and the worker. Every record carries the request id, which also returns in the `X-Request-Id` response header |

`GET /metrics` exposes Prometheus series — request rate, errors and latency by
route template, plus database pool utilisation. It is **unauthenticated** and
mounted outside `/api/v1`, because Prometheus scrapes it over the compose network
by service name; block it at the edge if the API is exposed directly. The bundled
`prometheus.yml` already scrapes it.

`GET /api/v1/health` reports the running version and the commit the image was
built from.

## Password reset (B05)

The forgot/reset flow needs a public URL to put in the email link and an SMTP relay (or the dev outbox) to deliver it. In `make dev` and the e2e suite, leaving `SMTP_HOST` empty activates the in-memory dev outbox — the email is logged at INFO and captured for `GET /api/v1/auth/debug/last-email` (mounted only when `ENVIRONMENT != "production"`). Production with `SMTP_HOST` empty refuses to deliver: the route turns the `RuntimeError` into a 5xx rather than silently dropping the email.

| Variable | Default | Description |
|---|---|---|
| `PUBLIC_URL` | `http://localhost:8077` | Base URL the reset link points to. The user clicks `${PUBLIC_URL}/reset-password?token=…` |
| `RESET_TOKEN_TTL_MINUTES` | `30` | Lifetime of the reset token. Tokens are single-use; once consumed (`used_at` non-null) they're rejected even within the TTL |
| `SMTP_HOST` | `` (dev outbox) | SMTP relay hostname. Leave empty in dev / e2e — the email is captured in-process instead |
| `SMTP_PORT` | `587` | SMTP relay port |
| `SMTP_USER` | `` | SMTP auth username (omit if your relay doesn't require auth) |
| `SMTP_PASSWORD` | `` | SMTP auth password |
| `SMTP_FROM` | `noreply@nis2.local` | `From:` header on outgoing emails |
| `SMTP_STARTTLS` | `true` | Issue `STARTTLS` after `EHLO` (the common case for ports 25 / 587) |
| `SMTP_SSL` | `false` | Wrap the entire connection in TLS (port 465 style). Mutually exclusive with `SMTP_STARTTLS` |

## Reports

Generated reports (PDF / HTML / Markdown / JSON / CSV / JUnit XML) live under `/tmp/nis2-reports/` on the Celery worker, shared with the API container via the `reports-data` Docker named volume. A daily Celery beat task (`cleanup-old-reports`) sweeps this directory of files older than the TTL — without it, the disk grows unbounded as users generate reports.

| Variable | Default | Description |
|---|---|---|
| `REPORT_TTL_DAYS` | `30` | Days to keep generated report files before the daily cleanup task deletes them. Long enough for a compliance team to download last week's report after a holiday; short enough that a deploy generating 100s of scans/day doesn't fill the disk in weeks. The cleanup task always runs at the schedule's wall-clock cadence regardless of this value (it just changes the cutoff age). |

## Celery

| Variable | Default | Description |
|---|---|---|
| `CELERY_BROKER_URL` | `redis://redis:6379/1` | Celery message broker |
| `CELERY_RESULT_BACKEND` | `redis://redis:6379/2` | Celery result backend |

## Frontend (Next.js)

| Variable | Default | Description |
|---|---|---|
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000` | Public API URL (client-side) |

`NEXTAUTH_URL`, `NEXTAUTH_SECRET` and `API_URL` were documented here and are not
read by anything: `next-auth` is not a dependency of `packages/web`. If your
`.env` still carries them they are inert.

## Production (Caddy)

| Variable | Default | Description |
|---|---|---|
| `DOMAIN` | `nis2.yourdomain.com` | Domain for Caddy auto-HTTPS. Set this for production deployments |

## Scanner Defaults

Scanner behavior is configured per scan via the API when creating a scan or schedule. Organization settings store defaults that new scans inherit. Key defaults in the scan creation endpoint:

- **Timeout**: 10 seconds per check (`scan_timeout`)
- **Concurrency**: 20 parallel tasks (`concurrency`)
- **Max hosts**: 0 (unlimited) -- configurable limit on targets per scan (`max_hosts`)
- **Features**: Individual check categories (`dns_checks`, `web_checks`, `port_scan`, `whois_checks`) can be toggled per scan. Organization settings store the defaults that new scans inherit.

## Organization Settings

Organization-level settings are managed through the dashboard under **Settings**:

- Organization name and metadata
- Default scan configuration (features, concurrency, timeout)
- Team member management (invite, role assignment)
- API key management
- Notification channel preferences
