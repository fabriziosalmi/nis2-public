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

2. **Edit `.env` for production:**

```bash
# Set your domain for Caddy auto-HTTPS
DOMAIN=nis2.yourdomain.com

# Generate secure secrets
JWT_SECRET=$(openssl rand -hex 32)
NEXTAUTH_SECRET=$(openssl rand -hex 32)

# Set strong database credentials
POSTGRES_PASSWORD=your-secure-password
DATABASE_URL=postgresql+asyncpg://nis2:your-secure-password@postgres:5432/nis2
DATABASE_URL_SYNC=postgresql://nis2:your-secure-password@postgres:5432/nis2

# Update frontend URLs
NEXTAUTH_URL=https://nis2.yourdomain.com
NEXT_PUBLIC_API_URL=https://nis2.yourdomain.com/api
```

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
