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

Scale workers to handle more concurrent scans:

```bash
docker compose -f infra/docker/docker-compose.prod.yml up -d --scale worker=4
```

Each worker process handles scan execution and report generation. Monitor queue depth in Redis to determine when to scale.

## Monitoring

### Prometheus

The platform exposes metrics for Prometheus scraping. Configure your Prometheus instance to scrape:

- API metrics: `http://api:8000/metrics`
- Celery worker metrics via the Redis exporter

A Prometheus instance is available on port `9099` in the dev stack.

### Health Check

The `/api/health` endpoint returns the status of all dependencies:

```bash
curl https://nis2.yourdomain.com/api/health
```

Returns: database connectivity, Redis connectivity, and Celery worker availability.

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
