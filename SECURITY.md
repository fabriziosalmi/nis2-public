# Security Policy

<!--
  Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
  SPDX-License-Identifier: AGPL-3.0-only
  NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
-->

This policy governs vulnerability reporting and handling for the NIS2 Compliance Platform open-source project. It is published in two places that should always be in sync:

- `SECURITY.md` (this file) — full text, GitHub renders it on the *Security* tab and on the project front page.
- [`/.well-known/security.txt`](packages/web/public/.well-known/security.txt) — RFC 9116-compliant machine-readable summary served at `https://<your-deployment>/.well-known/security.txt`.

## Supported versions

We support the **current minor** and the **previous minor** with security patches. Older minors are end-of-life — upgrade.

| Version | Status | Security patches |
|---------|--------|------------------|
| 2.5.x   | Current | Yes |
| 2.4.x   | Previous | Yes (until 2026-10-30) |
| ≤ 2.3   | End-of-life | No — please upgrade |

The platform is distributed under AGPL-3.0 §15-16 *as is, without warranty of any kind*. The maintainer's commitment to patch supported versions is good-faith and best-effort — read the LICENSE before relying on it for a production NIS2 obligation.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security report.** Public disclosure before a fix is available materially raises the risk to every operator running the platform.

### Preferred channel — GitHub private vulnerability reporting

Use the GitHub-native flow: `https://github.com/fabriziosalmi/nis2-public/security/advisories/new`. It gives the maintainer and the reporter a private workspace, integrates with the patch process, and produces a CVE-shaped advisory once the fix lands.

### Alternative — email

Send a report to `fabrizio.salmi@gmail.com`. Please include:

- A description of the vulnerability with CVSS-style scoring (vector, severity)
- Reproduction steps — ideally a minimal proof-of-concept against a fresh `make dev` clone
- Affected versions (commit SHA or git tag)
- The impact you believe a successful exploit would have on a deployer
- Whether you are willing to be credited in the fix advisory and, if so, how

For sensitive content, you may encrypt the email with PGP:

- Key fingerprint: `<TO BE PUBLISHED — see below>`
- Public key: `<TO BE PUBLISHED at https://github.com/fabriziosalmi.gpg once provisioned>`

> **PGP status (2026-04):** the maintainer has not yet published a permanent PGP key for security disclosures. While that is being provisioned, please prefer the GitHub private-vulnerability flow above (TLS in transit + access-controlled at rest), or request a Signal handle by replying to a routine email first. This section will be updated and the placeholder values replaced once the key is in place.

## Service-level commitments

Times are wall-clock from the maintainer's first acknowledgement of the report (not from when you submitted it). Best-effort, no warranty — see §1.

| Severity (CVSS v3.1) | First response | Patch / mitigation released |
|---|---|---|
| Critical (9.0–10.0) | within 24 hours | within 7 days |
| High (7.0–8.9) | within 48 hours | within 14 days |
| Medium (4.0–6.9) | within 5 business days | within 35 days |
| Low (< 4.0) | within 10 business days | best-effort, next minor |

The 35-day medium-severity ceiling reflects the disclosure window industry conventions converged on around the EU **Cyber Resilience Act** (Reg. EU 2024/2847) coming-into-force timeline. Once the CRA is fully applicable, this policy will be revised to align with whatever Annex-mandated reporting cadence applies to non-commercial open-source projects.

For an **actively exploited** vulnerability the project will publish a notice in `CHANGELOG.md`, on the GitHub Security advisory, and on the docs site landing within 24 hours of confirmation, even if the patched release is not yet ready — operators need lead time to apply a workaround.

## Coordinated disclosure

Default disclosure timeline: **90 days from initial report** or upon release of a fix, whichever is sooner. The maintainer will not silently sit on a confirmed report past 90 days without engaging the reporter on an extension.

Please give the project that 90-day window before any public disclosure. Reports filed and then publicly disclosed within hours leave every deployer exposed and ultimately reduce the population of operators willing to upgrade in the future.

The reporter is invited to coordinate the public advisory wording, attribution language, and embargo lift time.

## What is in scope

In scope for the security policy:

- The API (`packages/api/`) and its public HTTP routes
- The scanner (`packages/scanner/`) and its outbound network behaviour
- The web app (`packages/web/`) — XSS, CSRF, auth flows, deserialisation
- The Docker images and deployment artefacts in `infra/`
- The Postgres schema and Row-Level Security policies (a missing or wrong policy is a security bug)
- The MCP integration entry points
- Any documented integration in this repository (Caddy config, Celery tasks, etc.)

Out of scope:

- Self-modifications by the deployer (e.g. you patched out the SSRF check) — your fork, your problem
- Vulnerabilities in third-party dependencies that are already tracked by upstream — file the upstream first; we'll bump
- Findings from running the platform with documented insecure overrides (`RLS_SUPERUSER_OK=1`, `ENVIRONMENT=development` on the public internet, weak `JWT_SECRET`, etc.)
- Issues that require physical access to the host or root-on-host — those are deployment hygiene, not platform bugs
- Theoretical attacks against bcrypt, AES, TLS, or other primitives at strength levels we do not deviate from

## Security measures (what is implemented today)

This section describes the controls actually implemented in the codebase. Every claim corresponds to code that ships in the current `main` branch.

### Authentication and session management

- **JWT-based authentication** (`python-jose`, HS256). Every token carries a `jti` claim.
- **Tokens live in httpOnly cookies** for browser clients (`access_token`, `refresh_token`). JavaScript cannot read them — XSS does not by itself compromise the session.
- **CSRF double-submit cookie pattern** (`packages/api/app/middleware/csrf.py`). The SPA echoes the JS-readable `csrf_token` cookie as `X-CSRF-Token` on every state-changing request; mismatch → 403. The CSRF cookie is **rotated on every `/auth/refresh`** so a captured value has the same short lifetime as the access token, not the full refresh-token window. Bearer / API-key requests are exempt because cookies are not auto-attached.
- **Refresh-token rotation and revocation.** `/auth/refresh` revokes the consumed `jti` before minting the new pair (replay of a stolen refresh token fails on the second use). `/auth/logout` revokes the current `jti`. State is held in `revoked_tokens`; expired rows are pruned hourly by a Celery beat task.
- **Boot-time secret validation.** In production (`ENVIRONMENT=production`, the default), the API refuses to start if `JWT_SECRET` is unset, equals `change-me`, or is shorter than 32 characters; if `CORS_ORIGINS` is unset; if the DB role is `SUPERUSER` / `BYPASSRLS` (escape-hatch via `RLS_SUPERUSER_OK=1`).
- **Passwords** hashed with bcrypt (`passlib`).
- **Role-based access control** (`owner`, `admin`, `auditor`, `viewer`) per organisation membership.
- **Rate limiting** on auth endpoints via SlowAPI: 10/min on `/register` and `/login`, 20/min on `/refresh`, 5/min on `/forgot-password`.
- **`/forgot-password` constant-time response** — both the known-email and unknown-email paths perform the same CPU work and the same randomised latency-jitter, so response time is not a user-enumeration primitive. The MTA-failure log records `user_id` only, never the email address.
- **API key authentication** for CI/CD integrations. Keys are hashed (SHA-256) at rest; lookups go through an indexed equality query.
- **GDPR data-subject rights**:
  - `DELETE /api/v1/auth/me` (Art. 17) — re-auth, single-admin guard, lone-tenant cascade, audit-log pseudonymisation.
  - `GET /api/v1/auth/me/export` (Art. 20) — JSON export of profile, memberships, API-key metadata, audit logs.

### Network security

- **CORS** restricted to an explicit allow-list. The API refuses to start in production if `CORS_ORIGINS` is unset.
- **SSRF prevention** on all user-supplied URLs and IPs (`packages/api/app/utils/target_validator.py`): blocks RFC 1918, loopback, link-local, IPv6 ULA/link-local, CGN, and known cloud metadata addresses (169.254.169.254, fd00:ec2::254).
- **DNS rebinding mitigation.** The validator pins the IP it resolves at asset creation time. The scanner connects to that pinned IP (sending the original hostname as `Host` header) instead of re-resolving. Closes the TOCTOU window between asset creation and scan execution.
- **Security headers** set on every API response (`SecurityHeadersMiddleware`) and at the edge by Caddy (defence in depth): `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy: camera=(), microphone=(), geolocation=(), interest-cohort=()`, `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`, `Content-Security-Policy` with an explicit `frame-ancestors 'none'`.

### Multi-tenant isolation (defence in depth)

1. **Application layer.** Every protected query filters by `organization_id` derived from the authenticated session.
2. **Database layer (failsafe).** Postgres `FORCE` Row-Level Security on every tenant-scoped table. Each transaction issues `SET LOCAL app.current_org_id` from the JWT; the policy `organization_id::text = current_setting('app.current_org_id', true)` is enforced even if a router forgets its `WHERE` clause. `WITH CHECK` clauses block cross-tenant writes explicitly.
3. **Boot-time hard-fail** if the DB role is `SUPERUSER` or has `BYPASSRLS`, since RLS is decorative against such roles.
4. **Migrations bypass** via `SET LOCAL app.bypass_rls = 'on'` (set automatically by `alembic/env.py`).

### Audit logging

- **Auto-applied** by `AuditMiddleware` on every successful state-changing request (POST/PUT/PATCH/DELETE → 2xx). No router can forget to log an action. Captures method, path, status, `user_id`, `org_id`, IP, User-Agent. The richer per-call `log_action()` helper remains available for routers that want to record `resource_id` and a custom payload.
- Default retention 90 days, configurable via `AUDIT_LOG_RETENTION_DAYS`.

### Data protection

- No secrets stored in version control. CI runs `gitleaks` on every push; the allowlist is narrow and documented.
- `.env.example` contains only placeholder instructions; `prod-preflight` refuses to start with placeholder values.
- All container images run as non-root users.
- Findings list shows an in-product GDPR notice that scan evidence may include personal data and must be exported / shared with appropriate care.

### Supply chain hardening

- **GitHub Actions pinned by 40-character commit SHA** (not mutable tags).
- **Docker base images pinned by immutable manifest digest** in `packages/api/Dockerfile`, `packages/web/Dockerfile`, `packages/scanner/Dockerfile`.
- **Dependabot** enabled for pip (root, api, scanner), npm (web), Docker (root, api, web), and GitHub Actions.
- **`.dockerignore`** prevents `.env`, `.git/`, `.claude/`, `node_modules`, `__pycache__`, `.next/`, `.vscode/`, `.idea/` from entering images.
- **`npm ci`** for deterministic Node.js builds against a committed `package-lock.json`.
- **CI security gates**: `pip-audit` (Python deps), `npm audit` (web deps), `gitleaks` (secret detection), `trivy fs` (filesystem vulnerability scan).
- **Workflow permissions** declared minimally (`contents: read` by default).

### MCP integration

- The stdio MCP entry point is intended for local trusted use (Claude Desktop, Cursor) and is not exposed over HTTP.
- The HTTP MCP routes (`/api/v1/mcp/tools`, `/api/v1/mcp/call`) require an authenticated session and inherit the same RLS scoping as every other tenant-aware endpoint.

## Secrets management

See [docs/guide/secrets-rotation.md](docs/guide/secrets-rotation.md) for the rotation procedure covering:

- `JWT_SECRET`
- `NEXTAUTH_SECRET`
- Database credentials
- API keys

## Hall of fame

Reporters who responsibly disclosed a security issue and consented to be named are listed below in chronological order. Quiet acknowledgement (no public name) is also fine — the entry will read "Anonymous" with the date and a one-line summary.

*(No entries yet — be the first.)*

## Updates to this policy

Material changes are reflected in `CHANGELOG.md` and announced via a GitHub Release note. The `Last updated` line below tracks the SLA / scope text specifically.

*Last updated: 2026-04-30 — version 2.0 (matches platform v2.5.4)*
