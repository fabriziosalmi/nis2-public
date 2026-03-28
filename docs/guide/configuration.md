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

Scanner behavior is configured through the API and organization settings in the dashboard. Key defaults:

- **Timeout**: 10 seconds per check
- **Concurrency**: Parallel check execution per target
- **Max hosts**: Configurable limit on targets per scan
- **Feature toggles**: Individual check categories can be enabled/disabled per organization

## Organization Settings

Organization-level settings are managed through the dashboard under **Settings**:

- Organization name and metadata
- Default scan configuration
- Team member management (invite, role assignment)
- API key management
- Notification preferences
