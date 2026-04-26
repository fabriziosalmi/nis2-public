<p align="center">
  <img src="https://img.shields.io/badge/NIS2-Compliance%20Platform-0f172a?style=for-the-badge&logo=shield&logoColor=white" alt="NIS2" />
  <br />
  <img src="https://img.shields.io/github/v/release/fabriziosalmi/nis2-public?style=flat-square&color=10b981" alt="Release" />
  <img src="https://img.shields.io/github/license/fabriziosalmi/nis2-public?style=flat-square" alt="License" />
  <img src="https://img.shields.io/badge/i18n-6%20languages-3b82f6?style=flat-square" alt="i18n" />
  <img src="https://img.shields.io/badge/MCP-compatible-8b5cf6?style=flat-square" alt="MCP" />
  <img src="https://img.shields.io/badge/tests-51%20passing-10b981?style=flat-square" alt="Tests" />
</p>

# NIS2 Compliance Platform

Full-stack SaaS platform for automated **NIS2 Directive (EU 2022/2555)** compliance scanning, certificate intelligence, AI-powered remediation, and governance management.

> **Built for the Italian and European compliance market** — includes D.Lgs 138/2024 Art. 21 mapping, P.IVA detection, CSIRT Art. 23 incident reporting, and 6-language support.

## Key Differentiators

| Feature | Description |
|---------|-------------|
| **Deep Certificate Intelligence** | Full chain validation, CT log monitoring (crt.sh), OCSP, key strength analysis, expiry prediction |
| **Remediation Playbooks** | 15+ structured playbooks with copy-paste configs for Nginx, Apache, Caddy, IIS |
| **AI Remediation Copilot** | Context-aware finding explanations via local LLM (Ollama) or OpenAI |
| **Effort and Cost Estimator** | Auto-calculate remediation budget per finding and per scan |
| **MCP Server** | 7 tools for Claude Desktop, Cursor, and any MCP-compatible AI assistant |
| **6 Languages** | EN, IT, FR, DE, ES, PT — next-intl with cookie-based locale |
| **Enterprise Security** | Rate limiting, CSP headers, SSRF prevention, API key auth, secrets rotation |
| **NIS2 Governance** | 30-item weighted checklist mapped to D.Lgs 138/2024 articles |

## Architecture

```
packages/
  api/          # FastAPI backend — 14 routers, async, Celery workers
  scanner/      # Python compliance scanner engine (standalone CLI)
  web/          # Next.js 15 + shadcn/ui + next-intl (6 languages)

docs/           # VitePress documentation site
infra/          # Docker Compose, Caddyfile (auto-HTTPS)
```

## Quick Start

```bash
git clone https://github.com/fabriziosalmi/nis2-public.git
cd nis2-public
cp .env.example .env    # IMPORTANT: Generate real secrets (see comments in file)
make dev                # Start all services

# Open:
#   UI:       http://localhost:8077
#   API Docs: http://localhost:8000/docs
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | Next.js 15, React 19, shadcn/ui, Tailwind v4, Zustand, TanStack Query, Recharts, next-intl |
| **Backend** | FastAPI, SQLAlchemy (async), Pydantic v2, Celery, Redis, slowapi |
| **Database** | PostgreSQL 16 |
| **Scanner** | Python asyncio, aiohttp, dnspython, Playwright, python-whois |
| **Security** | CSP, HSTS, rate limiting, SSRF prevention, API key auth |
| **AI / MCP** | MCP Server (stdio + HTTP), Ollama/OpenAI integration |
| **Infrastructure** | Docker, Caddy 2 (auto-HTTPS), GitHub Actions CI |

## API Endpoints

14 router groups, 40+ endpoints under `/api/v1/`:

| Group | Key Endpoints |
|-------|--------------|
| **Auth** | Register, Login, Refresh, Me (rate-limited: 10 req/min) |
| **Scans** | CRUD, results, findings, cancel, compare |
| **Findings** | List, filter, bulk update, stats |
| **Assets** | CRUD, CSV import (SSRF-protected) |
| **Certificates** | Single check, bulk check, CT logs |
| **Remediation** | Playbooks, finding matcher, effort estimator, AI explain |
| **Incidents** | CSIRT Art. 23 reporting with taxonomy |
| **Governance** | 30-item checklist, weighted scoring, seed/reset |
| **API Keys** | Create, list, revoke (CI/CD integration) |
| **Reports** | Generate (PDF/JSON/CSV/MD/JUnit/HTML), download |
| **MCP** | Tool listing, HTTP tool calls |
| **Schedules** | Cron-based recurring scans |
| **Organizations** | CRUD, member management |
| **Health** | Liveness + readiness |

## Scanner Checks

| Category | Checks |
|----------|--------|
| **Ports** | 14 critical ports (SSH, RDP, SMB, MySQL, PostgreSQL, Redis, MongoDB) |
| **TLS/SSL** | Version, ciphers, weak protocol probing, cert expiry, chain validation |
| **Certificates** | Full chain, OCSP, CT logs, key strength, SAN coverage, pinning |
| **HTTP** | HSTS, CSP, X-Frame-Options, cookies, SRI, security.txt |
| **DNS** | DNSSEC, zone transfer, SPF, DMARC, DKIM, MX redundancy |
| **Secrets** | AWS keys, GitHub tokens, private keys, JWTs in responses |
| **Legal** | P.IVA (Italy), privacy policy, cookie banner (Playwright) |
| **Resilience** | WAF/CDN detection, version disclosure, SSH hardening |
| **WHOIS** | Domain expiry monitoring (30-day threshold) |

## MCP Integration

Expose the platform as AI tools for Claude Desktop, Cursor, or any MCP client:

```json
{
  "mcpServers": {
    "nis2-compliance": {
      "command": "python",
      "args": ["-c", "from app.mcp_server import run_mcp_stdio; run_mcp_stdio()"],
      "cwd": "packages/api"
    }
  }
}
```

**Available tools:** `check_certificate`, `scan_target`, `search_playbooks`, `get_playbook`, `estimate_remediation`, `list_governance_items`

## Internationalization

| English | Italiano | Francais | Deutsch | Espanol | Portugues |
|---------|----------|----------|---------|---------|-----------|

200+ translation keys covering all UI sections. Cookie-based locale switching — no URL changes needed.

## Development

```bash
make dev          # Start all services
make dev-down     # Stop services
make test         # Run all tests (51 passing)
make clean        # Stop + remove volumes
make prod         # Production stack with Caddy auto-HTTPS
```

## Documentation

- **API Docs**: `http://localhost:8000/docs` (interactive OpenAPI)
- **VitePress Site**: `docs/` directory
- **Secrets Rotation**: `docs/guide/secrets-rotation.md`

## Professional Services

This platform is maintained by **Fabrizio Salmi**, independent NIS2 compliance consultant.

Available services for organizations subject to the NIS2 Directive (EU 2022/2555) and D.Lgs 138/2024:

| Service | Description |
|---------|-------------|
| **Private NIS2 Compliance Scan** | White-label scanning and reporting for your infrastructure, with executive-ready deliverables |
| **Certificate Remediation** | End-to-end TLS/SSL certificate lifecycle management using CertMate and CertMate-NG |
| **Custom Readiness Assessment** | Gap analysis against all 10 NIS2 Art. 21 requirements, tailored to your sector |
| **Incident Response Consulting** | CSIRT notification support (Art. 23), incident taxonomy, timeline reconstruction |
| **Ongoing Compliance Monitoring** | Scheduled scans, trend analysis, and quarterly compliance reports |
| **Platform Customization** | Custom integrations, private deployments, sector-specific scanner modules |
| **Staff Training** | NIS2 awareness workshops, technical security training for development teams |

**Contact:** [fabrizio.salmi@gmail.com](mailto:fabrizio.salmi@gmail.com)

Related tools: [CertMate](https://github.com/fabriziosalmi/certmate) | [CertMate-NG](https://github.com/fabriziosalmi/certmate-ng)

## Contributing

Contributions welcome. Please open an issue first to discuss changes.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests (`make test`)
4. Commit your changes
5. Push and open a Pull Request

## License

AGPL-3.0 — see [LICENSE](LICENSE) file.

This means you can freely use, modify, and deploy this software. If you modify it and offer it as a service to others, you must make your modifications available under the same license. For commercial licensing options, contact [fabrizio.salmi@gmail.com](mailto:fabrizio.salmi@gmail.com).

## Links

- [Releases](https://github.com/fabriziosalmi/nis2-public/releases)
- [Issues](https://github.com/fabriziosalmi/nis2-public/issues)
- [Discussions](https://github.com/fabriziosalmi/nis2-public/discussions)
- [Professional Services](mailto:fabrizio.salmi@gmail.com)

