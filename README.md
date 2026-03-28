# NIS2 Compliance Platform

Full-stack SaaS platform for automated NIS2 Directive (EU 2022/2555) compliance scanning, reporting, and management. Built with FastAPI, Next.js 15, shadcn/ui, PostgreSQL, and Celery.

## Features

- **Automated Compliance Scanner** — 50+ security checks: ports, TLS/SSL, HTTP headers, DNS (DNSSEC, SPF, DMARC), WHOIS, WAF/CDN detection, secrets, SRI, legal compliance
- **NIS2 Art. 21 Compliance Matrix** — Maps all 10 subsections (a-j) of D.Lgs 138/2024 with automated/manual status tracking
- **Multi-tenant SaaS** — Organization-based isolation with role-based access (admin/auditor/viewer)
- **Admin Dashboard** — Real-time stats, compliance score trends, findings by severity charts (Recharts)
- **Findings Management** — Severity badges, status workflow (open/acknowledged/resolved), bulk updates, filtering
- **Report Generation** — PDF, JSON, CSV reports via async Celery tasks with download API
- **Scheduled Scans** — Cron-based recurring scans with Celery Beat
- **Scan Comparison** — Diff two scans: new/resolved/persistent findings with score delta
- **Asset Management** — Domains, IPs, CIDR blocks with tags and status tracking
- **Caddy Reverse Proxy** — Automatic HTTPS via Let's Encrypt, zero-config TLS
- **Italian Compliance** — P.IVA detection, privacy policy, cookie banner checks (Playwright)
- **Prometheus Metrics** — Scanner metrics export for monitoring

## Architecture

```
packages/
  scanner/    # Python compliance scanner engine (standalone CLI)
  api/        # FastAPI backend (29 endpoints, async, Celery workers)
  web/        # Next.js 15 + shadcn/ui + Zustand + TanStack Query
infra/
  docker/     # Docker Compose (dev + prod), Caddyfile
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 15, React 19, shadcn/ui, Tailwind v4, Zustand, TanStack Query, Recharts |
| Backend | FastAPI, SQLAlchemy (async), Alembic, Pydantic v2, Celery, Redis |
| Database | PostgreSQL 16 |
| Scanner | Python asyncio, aiohttp, dnspython, Playwright, python-whois |
| Infra | Docker, Caddy 2 (auto-HTTPS), Prometheus |

## Quick Start

```bash
# Clone
git clone https://github.com/fabriziosalmi/nis2-public.git
cd nis2-public

# Configure
cp .env.example .env

# Start development stack
make dev

# Open
# UI:       http://localhost:8077
# API Docs: http://localhost:8000/docs
```

### Development Commands

```bash
make dev          # Start all services (postgres, redis, api, celery, web)
make dev-down     # Stop services
make dev-logs     # Follow all logs
make api-logs     # Follow API logs
make web-logs     # Follow frontend logs
make test         # Run all tests
make clean        # Stop + remove volumes
make prod         # Start production stack with Caddy
```

## Production Deployment

```bash
# Set your domain
echo "DOMAIN=nis2.yourdomain.com" >> .env

# Deploy with auto-HTTPS
make prod
```

Caddy handles TLS certificates automatically via Let's Encrypt.

## API

29 REST endpoints under `/api/v1/`:

| Group | Endpoints |
|-------|-----------|
| Auth | `POST /register`, `/login`, `/refresh`, `GET/PATCH /me` |
| Scans | CRUD + `/results`, `/findings`, `/cancel`, `/compare/{id}` |
| Findings | List, filter, update status, bulk update, stats |
| Assets | CRUD + CSV import |
| Schedules | CRUD + trigger immediate run |
| Reports | Generate (PDF/JSON/CSV), status polling, download |
| Organizations | CRUD + member management (invite, roles) |
| Health | Liveness + readiness checks |

Full OpenAPI docs at `/docs` when the API is running.

## Scanner Checks

| Category | Checks |
|----------|--------|
| Ports | 14 critical ports (SSH, RDP, SMB, MySQL, PostgreSQL, Redis, MongoDB, FTP, Telnet) |
| TLS/SSL | Version, ciphers, weak version probing (TLS 1.0/1.1), certificate expiry |
| HTTP | HSTS, CSP, X-Frame-Options, cookies (Secure/HttpOnly/SameSite), SRI |
| DNS | DNSSEC, zone transfer (AXFR), SPF, DMARC, MX redundancy |
| Secrets | AWS keys, GitHub tokens, private keys, JWTs in responses |
| Legal | P.IVA (Italy), privacy policy, cookie banner (dynamic via Playwright) |
| Resilience | WAF/CDN detection, banner/version disclosure, SSH hardening |
| WHOIS | Domain expiry monitoring (30-day warning threshold) |

## Project Structure

```
packages/api/app/
  models/       # 11 SQLAlchemy models (User, Org, Scan, Finding, Asset, ...)
  routers/      # 8 FastAPI routers
  schemas/      # Pydantic request/response schemas
  services/     # Scanner adapter (scan_service.py)
  tasks/        # Celery tasks (scan, report, scheduled)
  middleware/   # Tenant isolation, audit logging

packages/web/src/
  app/dashboard/  # 16 pages (scans, assets, findings, compliance, reports, settings)
  components/     # shadcn/ui components + layout (sidebar, header)
  hooks/          # TanStack Query hooks
  stores/         # Zustand auth store
  lib/            # API client, utilities
```

## Contributing

Contributions welcome. Please open an issue first to discuss changes.

## License

MIT License - see LICENSE file for details.

## Links

- Issues: https://github.com/fabriziosalmi/nis2-public/issues
- Discussions: https://github.com/fabriziosalmi/nis2-public/discussions
