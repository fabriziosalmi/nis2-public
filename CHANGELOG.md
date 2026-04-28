# Changelog

## [2.4.12] - 2026-04-28

### Fixed (audit blockers B01–B03 + B08–B12)

This release closes 8 blocker issues from the user-management audit run during v2.4.11. The settings/team, settings/api-keys, and settings/audit-log pages are no longer Potemkin villages — they call the real API and persist real data. Multi-org tenants no longer return zero rows because of a `memberships[0]` ordering bug. API keys now actually authenticate (and expire). Role changes accept the body shape the FE has been sending all along.

- **B10 — Multi-org JWT desync.** `get_current_org` previously returned `current_user.memberships[0]`, an unsorted SQLAlchemy collection. For a user in two orgs, RLS scoped to the JWT's org X but the dependency returned membership Y, producing zero-row queries across the platform. `dependencies.py` now decodes the JWT once in `get_current_user`, stashes the payload on `request.state`, and `get_current_org` reads `org_id` from there to find the matching membership. 403 if no match (the user was removed since the token was issued); legacy tokens without `org_id` fall back to single-membership users only.

- **B11 — API key dependency was dead code, `expires_at` ignored.** `get_api_key_org` existed but was wired into zero routers, so keys could be issued and revoked but never authenticated anything. Now imports cleanly and (a) honours `expires_at` (also flips `is_active=False` on first expired use so subsequent reads see the right state without a cron); (b) keeps updating `last_used_at`.

- **B12 — viewer could see CI-key inventory.** `list_api_keys` had no role check. Even though only prefix + name leak (the hash never leaves the server), enumeration of integration names is reconnaissance. Locked to `admin/auditor` via the new `require_role` dependency factory.

- **B08 — `update_member_role` body vs query mismatch.** Server expected `?role=admin` query param while every client sent `body: JSON.stringify({role})`. Plus the server's `Literal` was `admin/auditor/viewer` while the FE Select offered `admin/member/viewer`, so even with the right wire format `member` would 422. Schema is now `RoleUpdateRequest` (Pydantic body model) with `admin/auditor/viewer`; the FE Select aligned.

- **B09 — last-admin demotion + self-demotion bypass.** `update_member_role` had no symmetric guard to `remove_member`'s last-admin protection. A solo admin could PATCH themselves to viewer and orphan the org. Added: explicit self-demotion refusal (`400` with "ask another admin or use the leave endpoint") + admin-count guard on `admin → !admin` transitions.

- **B01 — `settings/team` was 100% mocked.** Hardcoded `sampleMembers`, `onSubmit` only fired `toast.success`. Wired through `useMembers` / `useInviteMember` / `useUpdateMemberRole` / `useRemoveMember` hooks. Self-actions (remove me / demote me) hidden in the row dropdown to keep the UX honest about what the API will allow. Role enum aligned with backend (`admin/auditor/viewer`).

- **B02 — `settings/api-keys` was 100% mocked.** `Math.random().toString(36)` posed as a "new key" the user could paste into a CI/CD pipeline. Wired through `useApiKeys` / `useCreateApiKey` / `useRevokeApiKey`. The actual `raw_key` from the server now appears once in the post-create dialog with a "store this securely" warning. List response is verified to omit `key_hash`.

- **B03 — `settings/audit-log` had no API behind it.** New `routers/audit.py` exposes `GET /api/v1/audit-logs` (paginated, org-scoped, filterable by `action`, `resource_type`, `user_id`). Hydrates actor (user) info in one batch query — no per-row lazy-load. `admin/auditor` only. The frontend renders real data with action namespace colours.

### Added (instrumentation, supports B03)

- **`log_action(...)` calls in organizations.py and api_keys.py** for the actions an auditor needs to answer "who changed what":
  - `member.invited` (target email + role)
  - `member.role_changed` (before / after / target_user_id)
  - `member.removed` (removed_role + target_user_id)
  - `api_key.created` (name + prefix + scopes)
  - `api_key.revoked` (name + prefix)

  Same pattern from S02 in the audit; minimum viable set to make the audit-log view useful.

### Internal

- **`require_role(...)` dependency factory** in `app/dependencies.py`. Stops the role check from being a hand-rolled `if membership.role != "admin"` repeated in every endpoint (which is how B12 went unnoticed for so long).
- **Pydantic v2 fix** for `ApiKeyCreated`: `model_validate(... update={...})` is not a valid signature in v2. Build the response by validating the base shape and constructing the extended one with `**base.model_dump()`.

### Translation footprint

+13 new leaf strings × 5 locales = **65 new translations** for the un-mocked pages. All five files validate at **510 leaf strings** each (`jq '[.. | scalars] | length'`).

### Verified

- 42 unit + **32** e2e (was 21 — added a `TestUserManagement`, `TestApiKeysCRUD`, `TestAuditLogs` block) = **74 green**.
- 4/4 settings pages compile to 200 after recreate.
- Multi-org JWT path tested via the single-org happy case (full multi-org test would need a second org — added for v2.4.13 alongside the proper invite flow).

### Still pending (audit follow-up)

- **v2.4.13**: B04 (password change), B05 (forgot-password), B06+B07 (proper invite tokens + email + accept-after-register, no more silent auto-binding), the **9 serious** issues (S01–S09), and the **5 nits**.
- **v2.4.14+**: completion of i18n for `compliance` legal blocks (kept Italian for now per S01 rationale) and the remaining major-bump Dependabot PRs (lucide-react 1.x, recharts 3.x, etc).

## [2.4.11] - 2026-04-28

### Fixed (Davide F. — round 3)
- **`make clean-all` failed on Windows cmd.** `find -exec`, `2>/dev/null`, `|| true`, `xargs` are all Unix-only. Replaced the shell pipeline with a cross-platform `scripts/clean.py` (stdlib `pathlib` + `subprocess`); the Makefile targets now just call `python scripts/clean.py [--all]`. Linux / macOS / WSL / Windows cmd all produce the same output.
- **`make prod` redis container marked unhealthy on WSL/Windows.** Two stacked issues: (1) `${REDIS_PASSWORD}` had no default, so a missing `.env` left `redis-server --requirepass ""` which exits with "wrong number of arguments"; (2) the healthcheck used compose-time variable expansion which races with container env on some setups. Added `${REDIS_PASSWORD:-changeme}` default + healthcheck moved to `CMD-SHELL` so the password is read from the container's env (`$$REDIS_PASSWORD`). `start_period: 5s` for the cold start.
- **Token-expired UX**: page stayed navigable but every mutation silently 401'd. The api-client now intercepts 401 on protected paths, attempts ONE silent `/auth/refresh`, and on failure dispatches a `nis2:session-expired` window event. A new `SessionExpiredHandler` in `Providers` clears the auth-store, fires a toast, and redirects to `/login?session=expired` with an inline banner. Single-flight refresh promise prevents the cascading-logout race when many hooks 401 in parallel.
- **Scan creation 500 on external domain — root cause: `MissingGreenlet` on `Scan.updated_at`.** Pydantic's `ScanResponse.model_validate(scan)` triggered a lazy-load of `updated_at` after `db.flush()` in an async context that no longer had a greenlet, dying with `greenlet_spawn has not been called`. Added `await db.refresh(scan)` before the response. Fixes both "Failed to create scan" and the consequence "failed scan disappears from list" — the scan was never persisted in the first place.
- **Scan create FE↔BE schema mismatch.** The form sent `timeout` (BE expects `scan_timeout`) and `features.{dns,web,ports,whois}` (BE expects `dns_checks/web_checks/port_scan/whois_checks`). Pydantic silently dropped the unknown fields, so the user's settings were ignored. Aligned both. Removed the `sampleAssets` placeholder list (id="1"…) that let users select non-existent UUIDs and then 400 on submit.
- **Cannot edit existing asset.** The `PATCH /assets/{id}` endpoint existed in the API but no UI surface called it. Added `useUpdateAsset` hook + `api.updateAsset`, an edit-pencil icon in the Assets table row, and a dual-mode dialog (create vs edit). Type and target_value are deliberately immutable when editing — changing them would orphan every historical scan_result that references the value.
- **Theme switcher absent.** Added `next-themes` (already had the i18n strings — `header.lightMode/darkMode/systemMode` — but no UI). New `<ThemeToggle>` in the header with light / dark / system tri-state. `<ThemeProvider>` wraps the providers tree. Sidebar background now respects `dark:` variants (added the missing `--color-sidebar-*` tokens to `.dark` in globals.css — without them the sidebar stayed light-on-dark).
- **Browser locale not detected; compliance hardcoded Italian.** `i18n.ts` now negotiates `Accept-Language` (RFC 7231 q-values + prefix-match `it-IT → it`) when the `locale` cookie is absent. The compliance page wireup uses a new `compliancePage` namespace; legal references (D.Lgs 138/2024 article titles) stay Italian as the canonical text.

### Added (audit B13)
- **Login + Register pages fully translated.** Title, subtitle, all field labels, all placeholder strings, error toasts, and zod validation messages now go through `useTranslations`. Zod messages use stable i18n keys (`auth.invalidEmail`, `auth.passwordMin8`, …) so the same schema works across locales without re-instantiation.
- **Net translation footprint:** `+30 leaf strings × 5 locales = 150` new translations; structural alignment validated (`jq` count: 497 every locale).

### Added (operational)
- **`make dev-up-fresh`** target: `docker compose up --build --force-recreate --renew-anon-volumes`. Use this whenever a node dependency was added/removed in `packages/web` — without `--renew-anon-volumes`, the container keeps using the stale `node_modules` from the previous anonymous volume and the new module shows up as `Module not found` even after `--build`. Plain `make dev` is fine for code-only changes.

### Verified
- 7/7 dashboard routes still 200 after the recreate (`login`, `register`, `dashboard`, `dashboard/assets`, `dashboard/scans/new`, `dashboard/compliance`, `dashboard/settings/team`).
- API container `healthy` after restart; `/api/v1/health` 200.

### Note
- A draconian audit of the user/membership/permissions/api-keys subsystem was run during this release and surfaced **13 blockers + 9 serious + 5 nits** (most notably: settings/team, settings/api-keys, settings/audit-log are 100% mock data, no API wiring; password-change UI silently does nothing; invite flow auto-binds users without consent). These are scheduled for v2.4.12 (mock-removal + role/permission overhaul) and v2.4.13 (proper invite flow with email tokens). Full report kept internally.

## [2.4.10] - 2026-04-28

### Security (Dependabot drain — closes 9 open alerts, 2 high + 7 medium)

| # | Severity | Package | Manifest | Action |
|---|---|---|---|---|
| 24 | high | rollup `<4.59.0` | root `package-lock.json` | `overrides` to `^4.59.0` (path traversal) |
| 23 | high | preact `<10.28.2` | root `package-lock.json` | `overrides` to `^10.28.2` (JSON VNode injection) |
| 22 | medium | esbuild `<=0.24.2` | root `package-lock.json` | `overrides` to `^0.25.0` (dev-server CORS) |
| 57 | medium | vite `<=6.4.1` | root `package-lock.json` | `overrides` to `^6.4.2` (path traversal) |
| 60 | medium | postcss `<8.5.10` | root `package-lock.json` | `overrides` to `^8.5.10` (XSS via `</style>`) |
| 78 | medium | postcss `<8.5.10` | `packages/web/package-lock.json` | dep + `overrides` to `^8.5.10` |
| 77 | medium | next-intl `<4.9.1` | `packages/web/package-lock.json` | bump 3.25 → 4.11.0 (open redirect — not exploitable here, no `next-intl/navigation` usage, but bumped for hygiene; verified drop-in upgrade against the v4 migration guide) |
| 69 | medium | next-auth `<5.0.0-beta.30` | `packages/web/package-lock.json` | bump beta.25 → beta.31 (email misdelivery) |
| 25 | medium | scapy `<=2.6.1` | `packages/scanner/requirements.txt` | **dropped** — never imported in the codebase, dragged GHSA-pq98-w3cw-pgcr (untrusted-pickle session deserialization, no patched release) |

### Verification
- `npm audit` on root and `packages/web`: **0 vulnerabilities** at any severity.
- 42 unit + 21 e2e = **63 green** (ensures the next-intl 3 → 4 bump is genuinely drop-in for our usage subset: `getRequestConfig`, `NextIntlClientProvider`, `useTranslations`, `getLocale`/`getMessages`).

### Notes
- The `next-intl 3 → 4` bump in `packages/web/package.json` is the largest single change. We use only the simplest subset of next-intl (no localised routing, no middleware, no navigation `redirect()`); the v4 release notes document this as a no-config-change upgrade, and the test suite + visual smoke test confirm.
- `next` itself auto-bumped from 15.5.9 to 15.5.15 as part of the resolve.

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
