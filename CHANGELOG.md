# Changelog

## [2.4.9] - 2026-04-28

### Added
- **Dashboard screenshot in docs hero + README.** Replaced the small `/logo.svg` image in the VitePress hero with a proper 1208×683 product screenshot (`docs/public/screenshot.png`) and added it to the README under the badges. Gives visitors an immediate visual answer to "what does it look like?" without having to clone-and-`make-dev`.
- **Full i18n on 8 settings + asset pages** (round 1 of 3 staggered i18n patches). Pages now translated end-to-end (titles, subtitles, dialogs, table headers, empty states, button labels, toast messages, placeholders, validation copy) across 5 locales: `assets`, `scans/schedules`, `settings/{organization, scan-defaults, api-keys, audit-log, team, notifications}`. **Net: +156 leaf strings × 5 locales = 780 new translations**, structurally aligned across all 5 files (validated by `jq '[.. | scalars] | length'` returning 457 for every locale).

### Translation quality
- **EN + IT** — native-equivalent.
- **FR / DE / ES** — base-UI vocabulary, NIS2 / cybersec terminology kept as-is. Flagged for native-speaker review in a follow-up; structure is stable for PR contributions.

### Coverage status (after this release)
- ✅ **Full i18n** (titles, body, forms, toasts): dashboard, scans (list), findings, reports, **assets**, **scans/schedules**, profile, **settings/{organization, scan-defaults, api-keys, audit-log, team, notifications}** — 13 pages.
- ⏳ **Pending v2.4.10**: scans/new, scans/[id], scans/[id]/compare, compliance.
- ⏳ **Pending v2.4.11**: pt.json file (currently `i18n.ts` declares `pt` as a locale but the file doesn't exist), Zod validation message i18n refactor.

### Operational note
Editing `messages/*.json` and just `docker restart docker-web-1` is not enough — the anonymous `/app/.next` volume keeps a stale messages bundle. Use `docker compose -f infra/docker/docker-compose.dev.yml up -d --force-recreate web` (already documented in v2.4.7).

## [2.4.8] - 2026-04-28

### Fixed (reported by Davide F. — round 2)
- **`make prod` web container restart-loop** with `sh: next: not found`. The prod compose was overriding the Dockerfile CMD (`node server.js`) with `command: npm start` → `next start`, but the Next.js production stage builds a *standalone* bundle: only `.next/standalone/server.js`, `.next/static/` and `public/` are copied — no `node_modules`, no `next` binary. Removed the override; Dockerfile CMD runs unchanged.
- **`make prod` prometheus mount fails** with `not a directory: Are you trying to mount a directory onto a file (or vice-versa)?` on Docker Desktop / Windows. The `prometheus.yml` referenced by the compose did not exist in the repo, so Docker Desktop silently created an empty *directory* at the bind-mount source, and the mount then collided with the file path inside the container. Tracked `prometheus.yml` in the repo with a self+api+web scrape config.
- **`celery-beat` crash on WSL2** (`Errno 13` writing the schedule) — celery-beat's default scheduler is a SQLite-shelve file written to the working directory, which under `make dev` is bind-mounted from a Windows host through the `/mnt/c` proxy. SQLite POSIX locking semantics don't survive the round trip and beat exits on first write. `--schedule=/tmp/celerybeat-schedule` (dev) and a named `celerybeat_data` volume (prod) put the file on a docker-managed path. Linux hosts get a tiny perf bonus; WSL2 users get a working scheduler.

### Added
- **Sidebar / login / register: real logo.** Replaced the `N2` text-in-a-box placeholder with the inline-SVG `<Logo>` component (the same double-check artwork the docs site uses). `useId`-based gradient ids prevent the mobile/desktop instances from collidng on the same `url(#id)` reference. Favicon and Apple touch icon now also point at the same SVG via the root metadata, so browser tabs and PWA installs match the in-app brand.

### Fixed (audit-driven, latent)
- **`uvicorn --reload` not picking up edits on WSL2.** Same family as the Next.js polling fix from v2.4.3 — `watchfiles` (uvicorn's reload backend) relies on inotify, which doesn't propagate from `/mnt/c`. Added `WATCHFILES_FORCE_POLLING=true` to the dev API service.
- **Cold-start 502s through Caddy.** The API had no healthcheck and Caddy depended on `service_started`, so during the first 5–30s after `make prod` the proxy could route traffic at an API still doing RLS bootstrap. Added `/api/v1/health` healthcheck (uses `python urllib` to avoid pulling wget into the slim image), and switched Caddy's `depends_on` to `service_healthy`.
- **`make dev` / `make prod` returned before stack ready.** The Makefile printed "running at http://…" while containers were still warming up. Switched to `docker compose up -d --build --wait --wait-timeout 90` (Compose v2.20+); the URLs print only once everything declared healthy is healthy.

### Improved
- **`.env.example` default to `ENVIRONMENT=development`** (was production). Production-mode boot enforcement is opt-in. New users running `cp .env.example .env && make prod` no longer hit a refuse-to-start cascade. Added inline comments explaining the production-switch checklist (JWT_SECRET ≥32 chars, CORS_ORIGINS non-empty).
- **`.env.example` documents the dual-context for `DATABASE_URL`** — the `postgres:5432` host is correct for in-container use, the host-mapped `localhost:5433` for scripts run outside compose.
- **`make clean-all`** added — nukes `node_modules`, prod stack volumes, and per-project Docker images. Exists for the "guaranteed-fresh first run" scenario; the regular `clean` target preserves images and `node_modules` for cache reuse.
- **`packages/web/.dockerignore`** added. The repo-root `.dockerignore` does not apply to a sub-directory build context — without this, host `node_modules` and `.next` could leak into the Next.js build context (slow + bloated image).

### Verified
- API container healthcheck flips to `healthy` in <30s on a clean recreate.
- Test suite: 42 unit + 21 e2e = **63 green**.

## [2.4.7] - 2026-04-28

### Added (i18n: page content, not just navigation)
- **8 page namespaces translated** across all 5 supported locales (en, it, fr, de, es): `scans`, `findings`, `reports`, `profilePage`, `organizationPage`, `scanDefaultsPage`, `apiKeysPage`, `auditLogPage`. Total **301 leaf strings × 5 = 1505 translations**, structurally identical across locales (validated by `jq '[.. | scalars] | length'` returning 301 for each).
- **Scans / Findings / Reports / Profile pages** wired with `useTranslations`: titles, subtitles, table headers, empty states, filter labels, status badges, toast messages, format hints. Settings sub-pages (Organization, Scan Defaults, API Keys, Audit Log) translated at the **header level** (title + subtitle); deeper form fields kept in English for this iteration to keep the diff reviewable — open as follow-up if a non-English user reports friction.
- **EN + IT translations** are accurate (native-equivalent for IT — the project's primary deployment language). **FR / DE / ES** new keys use base-UI vocabulary based on standard cybersecurity terminology; flagged for native review in a follow-up.

### Fixed
- **`generateReport` 422** (already in v2.4.6 release notes — verifying it stays fixed under the i18n changes via the e2e suite).
- **Stale `.next` cache after volume-mount edits**: confirmed that with `infra/docker/docker-compose.dev.yml`'s anonymous `/app/.next` volume, message-file changes need `docker compose up -d --force-recreate web` rather than just `docker restart`. Documented in commit message.

### Notes
- Translation coverage holes (intentional for this release): page sub-routers like `scans/[id]`, `scans/new`, `scans/schedules`, `compliance`, `governance`, `incidents`, `remediation`, `vendors`, `bia`. Reach out (or open an issue) if any of these block your locale.

## [2.4.6] - 2026-04-28

### Fixed (UI consistency, reported live by maintainer)
- **`/dashboard/reports` was 404.** The sidebar navigated to `/dashboard/reports` but the page didn't exist. Built it: full table of completed scans with a per-row format selector (PDF / HTML / Markdown / JSON / CSV / JUnit XML), Generate button that queues the Celery task, polls `/reports/status/{task_id}` every 1.5s up to a 5-minute ceiling, then exposes a Download button that opens the FileResponse stream. Empty state nudges to `/dashboard/scans/new`.
- **`api-client.generateReport` was 422.** The FastAPI `/reports/generate` endpoint takes `scan_id` and `format` as **query parameters** (no Pydantic body model); the client was POSTing them as JSON. Switched to `URLSearchParams` on the URL.
- **Settings pages were narrow while the rest of the app is full-width.** `Profile`, `Organization`, `Scan Defaults`, `Notifications` had `<div class="space-y-6 max-w-2xl">` constraining content to ~672px on a wide layout. Removed the cap so they match Assets / Scans / Findings / API Keys / Team / Audit Log.
- **Hydration warning from browser-extension attributes.** ColorZilla / Grammarly / Dark Reader inject attributes (`cz-shortcut-listen`, `data-gr-*`) on `<body>` before React hydrates. Added `suppressHydrationWarning` on `<body>` (already present on `<html>` for `next-themes`). This silences only the attribute diff on this single element, not deeper-tree mismatches.

## [2.4.5] - 2026-04-28

### Fixed (caught by live e2e against the docker stack)
- **Schema drift: `assets.pinned_ip` column missing on existing volumes.** v2.4.0 added `pinned_ip: Mapped[Optional[str]]` to the `Asset` model for the DNS-rebinding TOCTOU mitigation, but no Alembic revision was ever generated — long-lived dev/CI volumes still had the old schema, so adding any asset 500'd with `column assets.pinned_ip does not exist`. Added an idempotent `ensure_schema()` step to the FastAPI lifespan: `Base.metadata.create_all` for missing tables, plus an explicit additive-column registry (`ALTER TABLE … ADD COLUMN IF NOT EXISTS`) for known drift. This is a stopgap — `alembic/versions/` should be populated before any production deploy and the registry is documented as DEBT in `database.py`.
- **RLS setup poisoned by single-transaction abort.** `setup_row_level_security` ran every `ALTER TABLE` inside one `engine.begin()`. The first failure on a non-existent table aborted the transaction, and every subsequent table failed with `InFailedSQLTransactionError: current transaction is aborted` — silently disabling RLS on 7+ tenant tables, exactly the failure mode RLS exists to prevent. Each table now runs in its own transaction. Verified in Postgres: 12/12 tenant-scoped tables show `relrowsecurity=t AND relforcerowsecurity=t`.
- **CSP blocked Next.js React Refresh in dev.** `script-src 'self' 'unsafe-inline'` (no `'unsafe-eval'`) tripped `Uncaught EvalError: Evaluating a string as JavaScript violates Content Security Policy` on every page reload. Now `'unsafe-eval'` and `ws:`/`wss:` are added to CSP **only** when `NODE_ENV !== 'production'`; the production build keeps the strict policy unchanged.
- **`slowapi` missing from `packages/api/pyproject.toml`** (caught by the post-rebuild `make dev`): API container failed to start with `ModuleNotFoundError: No module named 'slowapi'` even though `app/main.py` and `app/routers/auth.py` import it for rate limiting. Added `"slowapi>=0.1.9"` to dependencies.

### Added
- **`packages/api/tests/test_e2e_live.py`** — 21 end-to-end tests against a running stack (skipped automatically without `E2E_LIVE_BASE_URL`/`EMAIL`/`PASSWORD`). Covers: smoke (health, openapi), cookie HttpOnly verification on the raw set-cookie header, CSRF double-submit (no token → 403, wrong token → 403), full asset CRUD with the `pinned_ip` regression, 6 parametrised SSRF blocks (RFC1918, loopback, 169.254.169.254, localhost, metadata.google.internal, private CIDR), logout → /me 401. Total runtime: 1.7s. Run with the stack from `make dev`:
  ```bash
  E2E_LIVE_BASE_URL=http://localhost:8000 \
  E2E_LIVE_EMAIL=… E2E_LIVE_PASSWORD=… \
  pytest packages/api/tests/test_e2e_live.py -v
  ```

### Visual verification
- Login → dashboard renders clean, **zero console errors** (CSP fix verified). `Assets Monitored` reflects DB state in real time, proving the proxy/rewrite/cookie chain end-to-end.

## [2.4.4] - 2026-04-27

### Fixed (docs e2e review)
- **Docs were stale on GitHub Pages.** `deploy-docs.yml` only triggered on `paths: ['docs/**', '.github/workflows/deploy-docs.yml']`, so README, CHANGELOG and SECURITY changes never re-deployed the site. Dropped the path filter — the build is ~30s and always-fresh docs is worth more than the saved CI seconds. Also added `workflow_dispatch:` for manual runs.
- **Marketing claims still oversold in `docs/`.** The public docs still said "50+ checks" and "all 10 subsections" in four places (`docs/index.md`, `docs/guide/acn-compliance.md`, `docs/guide/services.md`) — the same wording we softened in `README.md` during the audit. Realigned: "30+ checks" and "all 10 sub-paragraphs (a)-(j) cross-referenced via the new `subparagraph` enum".
- **Determine ACN page missing CSIRT/24h deadlines.** Only the July 2027 baseline was listed; added the 31 December 2026 (CSIRT referent designation) and 1 January 2027 (24h Early Warning start) deadlines that the API already exposes via `/api/v1/deadlines`.
- **Determina 127437 export marked preliminary** in the docs to match the `"schema_version": "1.0-preliminary"` flag the API has been emitting since v2.4.0. The official ACN *modello di categorizzazione* publication (May/June 2026) will trigger a re-validation.
- **Mobile tables clipped cells.** `vp-doc table` had `overflow: hidden` so long API-reference rows got truncated under ~600px. Switched to `display: block; overflow-x: auto` for proper horizontal scrolling.

### Added (docs polish)
- **`og:image` (1200×630) at `/og.png`.** Social previews on LinkedIn, Slack, Telegram are now visual instead of text-only. Twitter card upgraded to `summary_large_image`. `theme-color: #0071e3` for browser chrome tinting.
- **JSON-LD `SoftwareApplication`** in `<head>` for rich Google search results.
- **`/.well-known/security.txt`** (RFC 9116) on the docs site itself — appropriate for a NIS2-themed product. Points to the SECURITY.md policy.
- **Footer links to Releases, Changelog, Security policy.** A "v2.4" dropdown in the navbar mirrors them in the top chrome.
- **LinkedIn social icon in the navbar** alongside GitHub. Lead capture from docs visitors.

## [2.4.3] - 2026-04-27

### Fixed (first-user feedback)
- **`make prod` web build failed** with `failed to compute cache key ... "/app/public": not found`. The web Dockerfile production stage `COPY --from=builder /app/public ./public` required the directory to exist, but `packages/web/public/` was never tracked in the repo. Added `packages/web/public/.gitkeep` so the directory ships even when empty. Drop in any static assets (favicon, og-image, robots.txt) here as they appear.
- **`make dev` left the browser on a "Loading..." white screen.** Two distinct causes, both fixed:
  - `next.config.ts` rewrites used `NEXT_PUBLIC_API_URL` as the proxy target. That env var is the *browser-facing* URL (`http://localhost:8000`); from inside the web container, `localhost` resolves to the container itself, so server-side rewrites silently failed. Added `INTERNAL_API_URL` (e.g. `http://api:8000`) which the rewrites prefer when set; falls back to `NEXT_PUBLIC_API_URL` for non-docker setups.
  - On Windows + Docker Desktop + WSL2, native filesystem events do not propagate from the host-mounted volume into the container, so Next.js' incremental dev compiler never completes the first build. Added `WATCHPACK_POLLING=true` and `CHOKIDAR_USEPOLLING=true` to the dev compose web service to force polling-based watching.

Reported by Davide Foresti (Essedieffe). Thanks Davide.

## [2.4.2] - 2026-04-27

### Fixed (RLS / integration tests — finishing what 2.4.1 started)
- **`SET LOCAL :param` rejected by Postgres.** SQLAlchemy was rendering `SET LOCAL app.current_org_id = :v` as `SET LOCAL app.current_org_id = $1`; Postgres' SET command does not accept bind parameters, so every request that scoped a session for RLS was 500-ing with `syntax error at or near "$1"`. Replaced with `SELECT set_config('app.current_org_id', :v, true)` — the parameterised, transaction-scoped equivalent.
- **`TestClient` cross-event-loop pool reuse.** When `INTEGRATION_DB=1`, the engine is created with `poolclass=NullPool` so each test gets a fresh asyncpg connection. The default pool retained connections attached to the first event loop pytest spun up, and `httpx`-driven follow-up tests on a new loop hit `Future attached to a different loop`.
- **`Secure` cookies not sent over `http://testserver`.** Integration tests now construct `TestClient` with `base_url="https://testserver"` so the production-like `Secure=True` flag on auth cookies still rides through.
- **CI postgres role for failsafe RLS testing.** The `postgres:16-alpine` image makes `POSTGRES_USER` a SUPERUSER and superusers always bypass RLS. The CI integration-tests job now provisions a dedicated `nis2_app` role with `NOSUPERUSER NOBYPASSRLS`; the API connects as that role so `FORCE ROW LEVEL SECURITY` actually binds it.

### Fixed (CI gates)
- **gitleaks** allowlist (`.gitleaks.toml`): documented test fixtures (canonical AWS docs sample key, generated RSA test keys in `packages/scanner/tests/test_features.py`) and the integration-tests JWT placeholder are no longer reported as leaks. Default rule set otherwise unchanged.
- **trivy fs**: bumped pinned version from 0.50.4 (asset removed from GitHub) to 0.70.0; bumped `aiohttp` 3.13.2 → 3.13.5 to close CVE-2025-69223 (HTTP Parser auto_decompress zip-bomb).
- **pip-audit**: pass `--skip-editable` so our own `pip install -e` packages don't fail PyPI lookup; upgrade `pip` itself first to clear CVE-2026-3219.

### Dependencies
- **Web**: `next` 15.1.0 → ^15.5.9 (closes critical Server Actions DoS GHSA-7m27-7ghc-44w9). Added `overrides` block forcing `lodash`/`lodash-es` to ^4.18.1 (recharts ships 4.17.23, vulnerable to GHSA-r5fr-rjxr-66jc and GHSA-f23m-r3pf-42rh; 4.18.1 is the patched release).
- **Scanner**: `aiohttp` floor lifted to >=3.13.3 in `pyproject.toml`, pinned 3.13.5 in `requirements.txt`.

### Notes
- This is a follow-up to 2.4.1, which introduced the RLS failsafe but tripped over Postgres bind-parameter and pytest-event-loop edge cases that only surfaced once the integration suite ran against a real Postgres in CI. CI is fully green on 2.4.2 (all 10 jobs).

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
