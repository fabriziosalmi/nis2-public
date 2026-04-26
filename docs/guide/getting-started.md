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

- Frontend: [http://localhost:8077](http://localhost:8077)
- API docs (Swagger UI): [http://localhost:8000/docs](http://localhost:8000/docs)

## First Steps

1. Register an account from the login page. Registration automatically creates an organization and assigns you the admin role.
2. Add assets -- enter the domains or IPs you want to scan.
3. Run a scan -- select one or more assets and click Start Scan.
4. Review findings in the dashboard. Each finding maps to a NIS2 article and includes severity and remediation guidance.

## Project Structure

```
nis2-public/
  packages/
    scanner/     # Python scanner (aiohttp, asyncio, dnspython, playwright)
    api/         # FastAPI backend (REST API, Celery task definitions)
    web/         # Next.js 15 frontend (shadcn/ui, Tailwind CSS)
  infra/
    docker/      # docker-compose.dev.yml, docker-compose.prod.yml
  scripts/       # DB seed, migration helpers
  docs/          # This documentation (VitePress)
```

## Make Targets

| Command | Description |
|---|---|
| `make dev` | Start all services in development mode |
| `make dev-down` | Stop development services |
| `make dev-logs` | Tail logs for all services |
| `make api-logs` | Tail API service logs |
| `make web-logs` | Tail frontend logs |
| `make db-migrate msg="description"` | Generate a new Alembic migration |
| `make db-upgrade` | Run database migrations |
| `make db-seed` | Seed database with sample data |
| `make test` | Run all tests (scanner + API) |
| `make test-scanner` | Run scanner tests only |
| `make test-api` | Run API tests only |
| `make prod` | Start production stack |
| `make prod-down` | Stop production stack |
| `make clean` | Remove containers, volumes, and caches |
