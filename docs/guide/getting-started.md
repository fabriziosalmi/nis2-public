# Getting Started

## Prerequisites

- Docker Engine 24+ and Docker Compose v2
- Git
- A Unix-like operating system (Linux or macOS). Windows works via WSL2.

For production, additionally:
- A server with ports 80 and 443 open
- A domain name with an A record pointing to that server

---

## Quick Start (Development)

### 1. Clone the repository

```bash
git clone https://github.com/fabriziosalmi/nis2-public.git
cd nis2-public
```

### 2. Create the environment file

```bash
cp .env.example .env
```

Open `.env` and at minimum set two secrets:

```bash
JWT_SECRET=$(openssl rand -base64 32)
DATA_ENCRYPTION_KEY=$(openssl rand -base64 32)
```

Replace the placeholder values in `.env` with the output of those commands. All other defaults work for local development. See [Configuration](./configuration.md) for the full variable reference.

### 3. Start the platform

```bash
make dev
```

This builds and starts all services: PostgreSQL, Redis, the FastAPI backend, a Celery worker, Celery Beat (scheduler), and the Next.js frontend. On first run, Docker pulls base images and builds local layers — allow a few minutes.

### 4. Open the dashboard

| Service | URL |
|---|---|
| Frontend dashboard | http://localhost:8077 |
| API (Swagger UI) | http://localhost:8000/docs |
| API (ReDoc) | http://localhost:8000/redoc |

---

## First Steps

### Register an account

Open http://localhost:8077 and click **Register**. Provide your name, email address, password, and an organisation name. Registration creates the organisation, assigns you the `admin` role, and signs you in automatically.

There is no pre-seeded admin account — the first registered user for an organisation is its admin.

### Add an asset

Navigate to **Assets** in the sidebar and click **Add Asset**. Enter:

- **Name**: a human-readable label (e.g. `Main website`)
- **Target type**: `domain`, `ip`, or `cidr`
- **Target value**: the actual domain or address (e.g. `example.com`, `192.168.1.0/24`)

Assets are the scan targets. Add all domains and IP ranges relevant to your NIS2 scope.

### Prove you may scan it

A new asset is `unverified`, and `POST /scans` refuses an unverified target with
a 403. That gate is deliberate: without it any account could point the scanner —
port scan, zone-transfer attempt, requests for `/.env` — at infrastructure it has
no relationship with, and the operator would answer for it.

Open the asset and choose the path that fits the target:

- **Domain** — issue a DNS TXT challenge, publish the record it gives you under
  `_nis2-challenge.<domain>`, then click check. This is evidence, the same
  mechanism as Let's Encrypt's DNS-01.
- **IP address or CIDR range** — these have no DNS to prove anything with, so an
  admin records a named, dated statement of authority instead. It is kept in the
  audit log, attributed to the person who made it.

Assets created before verification existed carry the `legacy` status and keep
working.

### Run a scan

Go to **Scans** and click **New Scan**. Select one or more assets and click **Start Scan**. The scan is queued as a Celery task and runs asynchronously. The status updates automatically: `pending` → `running` → `completed`.

### Review findings

Open **Findings** after the scan completes. Each finding maps to a NIS2 Art. 21 sub-paragraph, carries a severity (critical / high / medium / low / info), and includes a description and remediation guidance. Update the status of a finding (`acknowledged`, `in_progress`, `resolved`, `accepted_risk`) to track remediation progress.

---

## Project Structure

```
nis2-public/
  packages/
    scanner/    Python scanner — aiohttp, asyncio, dnspython, playwright
    api/        FastAPI backend — REST API, Celery task definitions, Alembic migrations
    web/        Next.js 15 frontend — shadcn/ui, Tailwind CSS
  infra/
    docker/     docker-compose.dev.yml, docker-compose.prod.yml, Caddyfile
  scripts/      Database seed and migration helpers
  docs/         VitePress documentation source
```

---

## Make Commands

| Command | Description |
|---|---|
| `make dev` | Build and start all services in development mode |
| `make dev-down` | Stop development services |
| `make dev-logs` | Stream logs from all services |
| `make api-logs` | Stream API service logs only |
| `make web-logs` | Stream frontend logs only |
| `make db-migrate msg="description"` | Generate a new Alembic migration |
| `make db-upgrade` | Apply pending database migrations |
| `make db-seed` | Populate the database with sample data |
| `make test` | Run the full test suite (scanner + API) |
| `make test-scanner` | Run scanner tests only |
| `make test-api` | Run API tests only |
| `make prod` | Start the production stack (Caddy, auto-HTTPS) |
| `make prod-down` | Stop the production stack |
| `make clean` | Remove containers, volumes, and build caches |

---

## Troubleshooting

**Port conflict on 5432 (PostgreSQL)**
If you have a local PostgreSQL instance running, stop it before starting the stack or change the host-side port mapping in `infra/docker/docker-compose.dev.yml`.

**`make dev` fails on first run with a database error**
The API starts before PostgreSQL is ready. Docker Compose health checks handle this, but on slow machines you may need to wait a moment and run `make dev` again, or watch the logs with `make dev-logs` until the postgres service shows `database system is ready to accept connections`.

**Changes to `.env` not taking effect**
Restart the affected service:
```bash
docker compose -f infra/docker/docker-compose.dev.yml restart api worker
```

See [Deployment](./deployment.md) for production setup and [Configuration](./configuration.md) for all environment variables.
