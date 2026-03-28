# Getting Started

## Prerequisites

- Docker and Docker Compose
- Git

## Quick Start

1. **Clone the repository:**

```bash
git clone https://github.com/fabriziosalmi/nis2-public.git
cd nis2-public
```

2. **Create your environment file:**

```bash
cp .env.example .env
```

Edit `.env` and set `JWT_SECRET` and `NEXTAUTH_SECRET` to random values. See [Configuration](./configuration.md) for all variables.

3. **Start the platform:**

```bash
make dev
```

This builds and starts all services: PostgreSQL, Redis, FastAPI, Celery worker, Celery Beat, and the Next.js frontend.

4. **Open the dashboard:**

Navigate to [http://localhost:8077](http://localhost:8077). The API docs are at [http://localhost:8000/docs](http://localhost:8000/docs).

## First Steps

1. **Register an account** from the login page.
2. **Create an organization** (or accept an invite to an existing one).
3. **Add assets** -- enter the domains or IPs you want to scan.
4. **Run your first scan** -- select an asset and click "Scan Now."
5. **Review findings** in the dashboard. Each finding maps to a NIS2 article and includes severity and remediation guidance.

## Project Structure

```
nis2-public/
  packages/
    scanner/     # Python CLI scanner (50+ checks)
    api/         # FastAPI backend (REST API, Celery tasks)
    web/         # Next.js 15 frontend (shadcn/ui)
  infra/
    docker/      # docker-compose.dev.yml, docker-compose.prod.yml
  scripts/       # DB seed, migration helpers
  docs/          # This documentation (VitePress)
```

## Useful Make Targets

| Command | Description |
|---|---|
| `make dev` | Start all services in development mode |
| `make dev-down` | Stop development services |
| `make dev-logs` | Tail logs for all services |
| `make api-logs` | Tail API service logs |
| `make web-logs` | Tail frontend logs |
| `make db-upgrade` | Run database migrations |
| `make db-seed` | Seed database with sample data |
| `make test` | Run all tests (scanner + API) |
| `make prod` | Start production stack |
| `make clean` | Remove containers, volumes, and caches |
