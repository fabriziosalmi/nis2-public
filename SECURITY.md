# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.4.x   | Yes       |
| < 2.4   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do NOT open a public issue.**
2. Email: [fabrizio.salmi@gmail.com](mailto:fabrizio.salmi@gmail.com) (or use GitHub's private vulnerability reporting).
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We aim to acknowledge reports within 48 hours and provide a fix within 7 days for critical issues.

## Security Measures

This section describes the controls actually implemented in the codebase. Every claim corresponds to code that ships in this repository.

### Authentication and session management
- **JWT-based authentication** (`python-jose`, HS256). Every token carries a `jti` claim.
- **Tokens live in httpOnly cookies** for browser clients (`access_token`, `refresh_token`), set/cleared by the API at `/login`, `/register`, `/refresh`, `/logout`. JavaScript can never read or steal them — XSS no longer compromises the session.
- **CSRF double-submit cookie pattern** (`packages/api/app/middleware/csrf.py`). The SPA echoes the JS-readable `csrf_token` cookie as `X-CSRF-Token` on every state-changing request; mismatch → 403. Bearer / API-key requests are exempt because cookies are not auto-attached.
- **Refresh-token rotation and revocation.** `/auth/refresh` revokes the consumed `jti` before minting the new pair (replay of a stolen refresh token fails on the second use). `/auth/logout` revokes the current `jti`. State is held in `revoked_tokens`.
- **Boot-time secret validation.** In production (`ENVIRONMENT=production`, the default), the API refuses to start if `JWT_SECRET` is unset, equals `change-me`, or is shorter than 32 characters; if `CORS_ORIGINS` is unset.
- **Passwords** hashed with bcrypt (`passlib`).
- **Role-based access control** (admin, auditor, viewer) per organization membership.
- **Rate limiting** on auth endpoints (10/min on `/register` and `/login`, 20/min on `/refresh`) via slowapi.
- **API key authentication** for CI/CD integrations. Keys are hashed (SHA-256) at rest; lookups go through an indexed equality query.

### Network security
- **CORS** restricted to an explicit allow-list. The API refuses to start in production if `CORS_ORIGINS` is unset.
- **SSRF prevention** on all user-supplied URLs and IPs (`packages/api/app/utils/target_validator.py`): blocks RFC 1918, loopback, link-local, IPv6 ULA/link-local, CGN, and known cloud metadata addresses.
- **DNS rebinding mitigation.** The validator pins the IP it resolves at asset creation time. The scanner connects to that pinned IP (sending the original hostname as Host header) instead of re-resolving. Closes the TOCTOU window between asset creation and scan execution.
- **Security headers** set on every API response (`SecurityHeadersMiddleware`): `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=()`, `Strict-Transport-Security: max-age=31536000; includeSubDomains`. Caddy adds equivalent headers at the edge in production deployments (defence in depth).

### Multi-tenant isolation (defence in depth)
1. **Application layer.** Every protected query filters by `organization_id` derived from the authenticated session.
2. **Database layer (failsafe).** Postgres FORCE Row-Level Security is applied to every tenant-scoped table. Each transaction issues `SET LOCAL app.current_org_id` from the JWT (set by `IdentityMiddleware`); the policy `organization_id::text = current_setting('app.current_org_id', true)` is enforced even if a router forgets its WHERE clause.
3. **Migrations bypass** via `SET LOCAL app.bypass_rls = 'on'` (set automatically by `alembic/env.py`).

### Audit logging
- **Auto-applied** by `AuditMiddleware` on every successful state-changing request (POST/PUT/PATCH/DELETE → 2xx). No router can forget to log an action. Captures method, path, status, user_id, org_id, IP, user-agent. The richer per-call `log_action()` helper remains available for routers that want to record resource_id and a custom payload.

### Data protection
- No secrets stored in version control.
- `.env.example` contains only placeholder instructions.
- All container images run as non-root users.

### Supply chain hardening
- **GitHub Actions pinned by 40-character commit SHA** (not mutable tags).
- **Docker base images pinned by immutable manifest digest**:
  - `python:3.12.7-slim-bookworm@sha256:60d9996b6a8a3689d36db740b49f4327be3be09a21122bd02fb8895abb38b50d`
  - `node:20.18.0-alpine3.20@sha256:b1e0880c3af955867bc2f1944b49d20187beb7afa3f30173e15a97149ab7f5f1`
- **Dependabot** enabled for pip (root, api, scanner), npm (web), Docker (root, api, web), and GitHub Actions.
- **`.dockerignore`** prevents `.env`, `.git/`, `.claude/`, `node_modules`, `__pycache__`, `.next/`, `.vscode/`, `.idea/` from entering images.
- **`npm ci`** for deterministic Node.js builds against a committed `package-lock.json`.
- **CI security gates**: `pip-audit` (Python deps), `npm audit` (web deps), `gitleaks` (secret detection), `trivy fs` (filesystem vulnerability scan).
- **Workflow permissions** declared minimally (`contents: read` by default).

### MCP integration
- The stdio MCP entry point is intended for local trusted use (Claude Desktop, Cursor) and is not exposed over HTTP.
- The HTTP MCP routes (`/api/v1/mcp/tools`, `/api/v1/mcp/call`) require an authenticated session and inherit the same RLS scoping as every other tenant-aware endpoint.

## Secrets Management

See [docs/guide/secrets-rotation.md](docs/guide/secrets-rotation.md) for the rotation procedure covering:
- `JWT_SECRET`
- `NEXTAUTH_SECRET`
- Database credentials
- API keys
