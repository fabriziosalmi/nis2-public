# Changelog

## [2.4.1] - 2026-04-26

### Fixed
- **Auth bootstrap could not write to RLS-protected tables.** `/auth/register`, `/auth/login`, `/auth/refresh` now set `app.bypass_rls = 'on'` for the duration of their transaction. Without this, the new `tenant_isolation` policy's `WITH CHECK` clause blocked the `memberships` INSERT during registration (`app.current_org_id` is unset before the user has a session) — the request returned 500 and the integration test suite failed.
- **AuditMiddleware could not write to `audit_logs`.** The middleware uses a session distinct from the request's `get_db()` session, which meant `app.current_org_id` was unset for the audit INSERT. The middleware now issues `SET LOCAL app.current_org_id = <org_id>` on its own session before adding the row, so the policy's `WITH CHECK` accepts the write.

## [2.4.0] - 2026-04-26

### Removed
- **Legacy `nis2_checker/` package** and its entire orbit (`tests/`, `simulation_server.py`, `targets.yaml`, `config.yaml`, `config_prod.yaml`, root `requirements.txt`, root `pyproject.toml`, root `Dockerfile`, root `docker-compose.yml`, `.gitlab-ci.yml`, root `governance_checklist.md`). Active development was already in `packages/`; the legacy directory was deprecated since 2.2 and is now gone.
- Branding response headers (`X-NIS2-Platform`, `X-NIS2-Contact`) — they leaked the maintainer's email address and a stale version string on every response.

### Security — session management
- **JWT in cookies, not localStorage.** `access_token` and `refresh_token` are now set as httpOnly cookies, removing the XSS-token-exfil class of bug that the previous Zustand-in-localStorage design exposed. Tokens are still returned in the response body for SDK and CLI consumers (Bearer-auth fallback).
- **CSRF double-submit pattern.** A non-httpOnly `csrf_token` cookie is issued at login; the SPA echoes it as the `X-CSRF-Token` header on state-changing requests. New `CSRFMiddleware` validates the match. Bearer / API-key requests are exempt (no automatic credential attachment, no CSRF risk).
- **Refresh-token rotation + revocation.** Every refresh and access token now carries a unique `jti` claim. `/auth/refresh` revokes the consumed token before minting a new pair, so replay of a stolen refresh token is rejected on the second use. `/auth/logout` revokes the current refresh token. New `RevokedToken` table with indexed lookups.
- **JWT_SECRET fail-fast in production.** The API refuses to start if `JWT_SECRET` is unset, equals `change-me`, or is shorter than 32 characters. Dev mode generates an ephemeral secret with a warning so `make dev` keeps working out of the box.
- **CORS fail-fast in production.** `CORS_ORIGINS` must be set explicitly (no localhost fallback).

### Security — defence in depth
- **Postgres Row-Level Security as failsafe.** New `IdentityMiddleware` decodes the JWT once at request entry and exposes user/org id via contextvars. `get_db` issues `SET LOCAL app.current_org_id` on every transaction; FORCE-RLS policies are applied idempotently to every tenant-scoped table at lifespan startup. If a router ever forgets a `WHERE organization_id = ...` clause, RLS still returns zero rows. Alembic migrations bypass via `app.bypass_rls`.
- **Auto-applied audit log.** New `AuditMiddleware` writes one `audit_logs` row per successful state-changing request (POST/PUT/PATCH/DELETE → 2xx), capturing method, path, status, user_id, org_id, IP and user-agent. No router can forget to log an action.
- **MCP HTTP routes auth-gated.** `/api/v1/mcp/tools` and `/api/v1/mcp/call` now require `Depends(get_current_user_org)`. The stdio entry point stays free for local trusted use.
- **Security headers middleware.** Every API response carries `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, `Strict-Transport-Security`. Caddy still sets the same headers at the edge in production (defence in depth).
- **DNS rebinding mitigation.** `target_validator` now resolves and pins the IP at validation time; `Asset.pinned_ip` persists it; the scanner connects to that pinned IP (with the original hostname as Host header) instead of re-resolving. Closes the TOCTOU window between asset creation and scan execution.

### Substantive NIS2 coverage
- **Art. 21 (a)–(j) machine-readable mapping.** `GovernanceItem.subparagraph` is now a constrained enum (validated at module load against a curated `SUBPARAGRAPHS` table). All 30 checklist items are tagged explicitly, including correcting items that previously double-tagged 21.2.f/21.2.g for cryptography content. New endpoints: `GET /governance/subparagraphs` (catalogue) and `GET /governance/by-subparagraph` (per-subparagraph completion stats). New filter on `GET /governance?subparagraph=21.2.b`.
- **ACN export marked preliminary.** Both `/acn-export/art18` and `/acn-export/bia` JSON now carries `"schema_version": "1.0-preliminary"` and a `"schema_status"` disclaimer until the official ACN *modello di categorizzazione* is published.

### Container hardening
- `packages/api/Dockerfile` and `packages/web/Dockerfile` now run as non-root users (`api`, `nextjs`, both uid 1001).
- All Docker base images now pinned by **immutable manifest digest**, not just patch tag:
  - `python:3.12.7-slim-bookworm@sha256:60d9996b6a8a3689d36db740b49f4327be3be09a21122bd02fb8895abb38b50d`
  - `node:20.18.0-alpine3.20@sha256:b1e0880c3af955867bc2f1944b49d20187beb7afa3f30173e15a97149ab7f5f1`

### Supply chain
- CI workflows (`ci.yml`, `nis2.yml`) now declare minimal `permissions:` (was permissive by default).
- New CI security gates: `pip-audit` (Python deps), `npm audit` (web deps), `gitleaks` (secret detection), `trivy fs` (filesystem vulnerability scan).

### Documentation
- README claims realigned with code: scanner check count corrected to "30+", language count corrected to 5 (was incorrectly listed as 6 with a Portuguese column that did not exist), translation key count corrected to 189, "all 10 sub-paragraphs" softened to honestly describe what the platform automates vs. what stays manual.
- SECURITY.md no longer claims controls that aren't implemented; current claims hold.

### Notes
- Versions 2.2.0 through 2.3.6 were tagged but their changelog entries were not maintained. From 2.4.0 onwards, every release will land a changelog entry. Refer to git history for incremental changes between 2.1.0 and 2.4.0.

---

## [2.1.0] - 2026-02-12

### Added
- **10x Architecture**: Fully asynchronous plugin-based scanning engine.
- **httpx Integration**: Switched to `httpx` with HTTP/2 support for faster concurrent scanning.
- **WebScannerPlugin**: Refactored web-based compliance checks (headers, P.IVA, Privacy).
- **CompliancePlugin**: Dedicated engine for vulnerability disclosure (security.txt).
- **InfrastructurePlugin**: Async SSL/TLS and DNS verification.
- **GovernanceEngine**: Initial support for automated markdown-based compliance tracking.

### Changed
- Refactored `ScannerLogic` to use parallel plugin orchestration.
- Updated `main.py` for full async execution.
- Improved compliance scoring weights.

### Fixed
- Fixed sequential bottleneck in large CIDR scans.
