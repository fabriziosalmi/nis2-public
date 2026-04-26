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

## Celery

| Variable | Default | Description |
|---|---|---|
| `CELERY_BROKER_URL` | `redis://redis:6379/1` | Celery message broker |
| `CELERY_RESULT_BACKEND` | `redis://redis:6379/2` | Celery result backend |

## Frontend (Next.js)

| Variable | Default | Description |
|---|---|---|
| `NEXTAUTH_URL` | `http://localhost:8077` | NextAuth base URL |
| `NEXTAUTH_SECRET` | (change in production) | NextAuth encryption secret |
| `API_URL` | `http://localhost:8000` | Internal API URL (server-side) |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000` | Public API URL (client-side) |

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
