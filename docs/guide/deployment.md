# Deployment

## Production Stack

The production deployment uses `docker-compose.prod.yml` with Caddy as a reverse proxy for automatic HTTPS.

### Prerequisites

- A server with Docker and Docker Compose installed
- A domain name with DNS pointing to your server
- Ports 80 and 443 open

### Steps

1. **Clone and configure:**

```bash
git clone https://github.com/fabriziosalmi/nis2-public.git
cd nis2-public
cp .env.example .env
```

2. **Edit `.env` for production.**

`.env.example` is the authoritative reference — it carries every variable with
the reason it matters, and copying it in step 1 already gives you the right
shape. What follows is only the set you must change; do not replace the database
URLs with a single superuser connection, which earlier versions of this guide
told you to do and which the API now refuses to start with.

```bash
# Caddy uses this for automatic HTTPS.
DOMAIN=nis2.yourdomain.com

# Secrets. Each must be at least 32 characters; the API refuses to boot on a
# placeholder or a short value, naming the key it rejected.
JWT_SECRET=$(openssl rand -base64 32)
DATA_ENCRYPTION_KEY=$(openssl rand -base64 32)   # MFA seeds, channel credentials
POSTGRES_PASSWORD=$(openssl rand -base64 24)     # bootstrap/DDL identity
NIS2_APP_PASSWORD=$(openssl rand -base64 24)     # runtime identity (see below)
REDIS_PASSWORD=$(openssl rand -base64 24)

# Where the browser reaches the API.
NEXT_PUBLIC_API_URL=https://nis2.yourdomain.com/api
CORS_ORIGINS=https://nis2.yourdomain.com
```

**Two database identities, and why.** Tenant isolation rests on Postgres
row-level security, and Postgres bypasses RLS unconditionally for SUPERUSER and
BYPASSRLS roles — `FORCE ROW LEVEL SECURITY` does not bind them either. So the
application must connect as a plain role, and something else must own the schema:

| Variable | Role | Used for |
|---|---|---|
| `DATABASE_URL` | `nis2_app` (NOSUPERUSER NOBYPASSRLS) | every request and task |
| `MIGRATION_DATABASE_URL` | `nis2` (bootstrap) | Alembic and the boot-time RLS setup |

`nis2_app` is provisioned on first volume initialisation by
`infra/docker/initdb/01-create-app-role.sh`, using `NIS2_APP_PASSWORD`. Both URLs
are already correct in `.env.example`; you only supply the two passwords.

The API asserts at startup that its runtime role is neither SUPERUSER nor
BYPASSRLS and **refuses to serve** otherwise, because every RLS policy would be
decorative. If you must defer that — an existing single-role deployment being
migrated — set `RLS_SUPERUSER_OK=1` and read `UPGRADING.md`.

`NEXTAUTH_SECRET` and `NEXTAUTH_URL` appeared in earlier versions of this guide.
`next-auth` is not a dependency of `packages/web` and nothing reads them; if your
`.env` still carries them they are inert and can be deleted.

3. **Start production services:**

```bash
make prod
```

Caddy automatically obtains and renews TLS certificates from Let's Encrypt.

## Caddy Configuration

Caddy serves as the reverse proxy, routing:

- `/` to the Next.js frontend
- `/api/*` to the FastAPI backend
- `/docs` and `/redoc` to the OpenAPI documentation

TLS certificates are managed automatically. No manual certificate setup is required.

## Database Backup

Back up PostgreSQL data regularly:

```bash
# Dump the database
docker compose -f infra/docker/docker-compose.prod.yml exec postgres \
  pg_dump -U nis2 nis2 > backup_$(date +%Y%m%d).sql

# Restore from backup
cat backup_20260101.sql | docker compose -f infra/docker/docker-compose.prod.yml exec -T postgres \
  psql -U nis2 nis2
```

Automate backups with a cron job on the host.

## Scaling Celery Workers

Scale the Celery worker service to handle more concurrent scans:

```bash
docker compose -f infra/docker/docker-compose.prod.yml up -d --scale celery-worker=4
```

Each worker process handles scan execution and report generation. Monitor queue depth in Redis to determine when to scale.

## Monitoring

### Health Checks

The API exposes two health endpoints:

- `GET /api/v1/health` -- returns `{"status": "ok"}`. Use this for load balancer liveness probes.
- `GET /api/v1/health/ready` -- checks database and Redis connectivity. Returns `{"status": "ok", "checks": {...}}` or `{"status": "degraded", "checks": {...}}`.

```bash
curl https://nis2.yourdomain.com/api/v1/health/ready
```

### Prometheus

A Prometheus instance is available on port `9099` in the dev stack. The scanner writes `.prom` text files for metrics collection. FastAPI does not expose an HTTP `/metrics` endpoint directly.

## Updating

To deploy a new version:

```bash
git pull origin main
make prod
```

Docker Compose rebuilds changed images and restarts affected services. Run migrations if needed:

```bash
make db-upgrade
```
