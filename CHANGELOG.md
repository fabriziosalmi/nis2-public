# Changelog

## [2.5.3] - 2026-04-30

External-reviewer feedback round (Davide, fresh-clone walkthrough). Four concrete fixes — one runtime blocker, one onboarding trap, one operability paper-cut, one orientation gap.

### 🟠 Fixed — Hydration error blocking the public landing on first load

**Symptom (reported by Davide)** — fresh `git clone`, `make dev`, navigate to `http://localhost:8077/`: the page rendered briefly then the React DevTools panel surfaced a "Recoverable Error — Hydration failed because the server rendered text didn't match the client" overlay, and the legal-disclaimer modal (added in v2.5.2) intermittently appeared then disappeared.

**Root cause** — `LegalDisclaimerModal` rendered the full `<div role="dialog">…</div>` tree on the server with `show=false`, then on the client a `useEffect` flipped `show=true` on first paint when localStorage said the visitor had not accepted. Even though the *outer* gate was a state flag, the rendered children (`useTranslations`, lucide icons, `<Button>`) introduced enough microscopic SSR↔CSR variation under React 19 + Next 15 strict hydration to register as a mismatch.

**Fix** — `packages/web/src/components/legal/legal-disclaimer-modal.tsx`: added a `mounted` state set by a `useEffect`, and gate the *entire* render behind it. The component now returns `null` on the server and during the very first client render; the dialog appears ~1 frame after hydration. Same pattern is documented inline in the file with the trade-off (~50ms blank-state) which is the same UX accepted by the v2.5.2 design.

### 🟠 Added — Python 3.10+ documented in README "Prerequisites"

**Symptom (reported by Davide)** — `make clean-all` exited with `Python non trovato — eseguire senza argomenti per installare dal Microsoft Store` on his Windows host. Same kind of failure was patched defensively in v2.4.28 with a Python interpreter probe in the Makefile, but the README still didn't *tell* a fresh installer that Python is required at all.

**Fix** — `README.md` now opens the install section with an explicit table:

| Tool | Required for |
|---|---|
| Docker + Docker Compose v2 | Running the dev/prod stack |
| GNU Make | `make dev`, `make prod`, `make clean*` targets |
| Python 3.10+ | `make clean*` (cross-platform clean script), `make test*` |
| openssl | Generating `JWT_SECRET` / `NEXTAUTH_SECRET` for production |

Plus a Windows-specific callout: the Microsoft Store stub at `%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe` is **not** a real Python — disable the App Execution Aliases for `python.exe` / `python3.exe` and install from python.org.

### 🟠 Improved — `make prod` pre-flight error formatting

**Symptom (reported by Davide)** — when `.env` is missing or `JWT_SECRET` is the placeholder, the previous one-line error sentences ran together with the shell prompt and were trivial to scroll past. The mitigation steps were buried at the end of the message, so the operator's eye landed on the *symptom* and missed the *fix*.

**Fix** — `Makefile` `prod-preflight`: rewrote each error block as a banner-separated stanza with explicit numbered steps and the exact commands to run. Example for missing `.env`:

```
===================================================================
  ERROR -- .env is missing
===================================================================

  Step 1) Copy the example file:

      cp .env.example .env

  Step 2) Open .env in an editor and set these variables:

      POSTGRES_PASSWORD   (any non-empty string)
      JWT_SECRET          (run:  openssl rand -base64 32 )
      ...

  Step 3) Re-run:  make prod
```

Same structural rewrite applied to the `POSTGRES_PASSWORD` / `JWT_SECRET=GENERATE_ME` / short-`JWT_SECRET` / missing-`CORS_ORIGINS` / `RLS_SUPERUSER_OK=1` warning paths.

### 🟠 Added — Dashboard orientation card explaining the Art. 21 / Art. 18 mapping

**Symptom (reported by Davide)** — after `make dev`, signup, and landing on `/dashboard`, the user could not figure out what the platform was actually *for*. The empty stat cards and the "New Scan" CTA gave no hint of the link between a TLS/DNS/header scan result and the NIS2 sub-paragraphs the result eventually weakens. The sidebar showed "Compliance", "Governance", "Vendors" as separate routes with no narrative explaining why all three exist.

**Fix** — `packages/web/src/app/dashboard/page.tsx`: new dismissible `OrientationCard` rendered between the page header and the stat-cards row. The card summarises in 30 seconds:

> **Cosa fa la piattaforma — in 30 secondi**
>
> La Direttiva NIS2 (UE 2022/2555) all'Art. 21(2) elenca dieci misure di gestione del rischio. L'Italia le ha recepite all'Art. 24(2) del D.Lgs 138/2024. La piattaforma copre quel terreno con tre superfici complementari:
>
> - **Scansioni** — controlli automatici su TLS, DNS, header HTTP, porte, certificati e secret. Ogni finding è mappato al sub-paragrafo dell'Art. 21(2) (a–j) che indebolisce. Copre circa il 30 % dell'Art. 21 — la parte tecnicamente osservabile.
> - **Checklist di Governance** — 30 voci che coprono gli obblighi umani / organizzativi che la sonda non può validare. Euristica didattica mappata sull'Art. 21(2), **non** riproduzione integrale del framework ACN.
> - **Fornitori / Supply chain** — obblighi Art. 18: inventario, scoring, contratti, campi specifici ACN. Tracciato separatamente dall'Art. 21.
>
> [ Apri la matrice ] [ Ho capito ]

Implementation notes:
- Dismissible — `localStorage` versioned key `nis2-dashboard-orientation-v1`. Once the user has internalised the mapping it stays out of the way; bumping the version forces re-display when a future surface (or a renamed Article reference) lands.
- Same SSR-empty-tree pattern as `LegalDisclaimerModal` — `mounted` flag avoids hydration mismatches.
- Bold spans rendered via `next-intl` `t.rich()` with a `<b>` placeholder — markup stays out of the JSON, ICU placeholders are validated at compile time.
- Translation parity: 7 keys × 5 locales (`dashboard.orientation{Title,Intro,Scans,Governance,Vendors,Cta,Dismiss}`) = 35 new i18n entries. en/it/fr/de/es all aligned.
- "Apri la matrice" CTA links to `/dashboard/compliance` — the visual matrix where each Art. 21(2) sub-paragraph (a–j) is shown alongside the scanner-observable findings that map to it.

### Misc

- `API_VERSION` literal bumped 2.5.2 → 2.5.3 in lockstep with `pyproject.toml`.
- `.gitleaks.toml`: added `nis2-dashboard-orientation-v\d+` to the localStorage-key allowlist family.

### Verified

- Web build: green (24/24 pages, /dashboard at 8.19 kB / 157 kB First Load JS).
- 5/5 i18n locales validate; `dashboard.orientation*` namespace present and aligned (7 keys × 5 locales = 35 entries).
- `make prod-preflight` against an empty `.env`, a `.env` with placeholder `JWT_SECRET`, and a `.env` with `RLS_SUPERUSER_OK=1` all surface the new banner-formatted messages.

## [2.5.2] - 2026-04-30

Legal-disclaimer interstitial — first-visit consent dialog for the public landing surfaces.

### 🟠 Added — Blocking legal-notice modal on the public landing pages

The public app landing (`/`) and the docs landing (`fabriziosalmi.github.io/nis2-public/`) now show a first-visit blocking dialog before any of the marketing surface is reachable:

> **Avviso Legale** — Questo strumento fornisce classificazioni automatizzate basate su un sottoinsieme della Direttiva NIS2 (UE 2022/2555). Non costituisce consulenza legale. Consultare un avvocato qualificato per determinare gli obblighi applicabili.
>
> Termini di utilizzo · Privacy Policy
>
> [ Ho compreso — Procedi ]

**Why** — three concrete legal benefits:

1. **GDPR Art. 13** — the regulation requires the data subject be informed *at the moment* personal data is obtained. A blocking dialog with the privacy notice linked guarantees the visitor cannot deny having seen it. This becomes load-bearing if a deployer is ever asked to demonstrate the chain-of-disclosure.
2. **Defence against reliance claims** — a downstream user who later argues "the platform told me I was compliant" runs into a click-through consent log saying "I understand, this is not legal advice". Pairs with the dashboard's compliance-page yellow alert (added in v2.5.0) and the scope clause in `docs/terms.md`.
3. **Coherence with sister NIS2 projects** — same UX pattern used across the maintainer's NIS2 portfolio. Consolidates user expectation rather than introducing a new consent flow.

**Implementation:**

- `packages/web/src/components/legal/legal-disclaimer-modal.tsx` — React component, mounted at the top of the unauthenticated landing. Suppressed for authenticated users (they accepted at register time and re-acknowledging on every dashboard visit would be noise). Body scroll locked while the dialog is open. Backdrop is `bg-slate-950/95 backdrop-blur-sm` so the marketing surface behind is dimmed but not jarring.
- Acceptance persisted in `localStorage` under a **versioned** key (`nis2-legal-disclaimer-v1`). Bumping the version on a future material revision of Terms or Privacy will force every prior visitor to re-acknowledge — acceptance against a stale text has no legal value.
- Translation in **all 5 locales** (en/it/fr/de/es) under `landingPage.legalDisclaimer.{title,body,terms,privacy,accept}`. 25 new i18n keys, parity 5/5.
- Mirror Vue component for the docs site lives inline in `docs/.vitepress/theme/components/Home.vue`. Distinct localStorage key (`nis2-doc-legal-disclaimer-v1`) — different origin, distinct consent. Same UX, dual-locale EN+IT consistent with the rest of the docs home.
- Terms + Privacy links in the dialog point to the canonical `docs/terms.md` and `docs/privacy.md` on GitHub (open in new tab) so the visitor can read them before clicking through.

**What it doesn't do** (deliberate):
- Does not gate the **dashboard** routes. Authenticated session = prior acceptance via the register flow.
- Does not rewrite the rendered HTML pre-paint via inline `<head>` script. The dialog appears within ~50–100ms of first paint via React/Vue hydration. This is a UX trade-off accepted for now; if the brief flash of un-disclaimed landing turns out to be a real issue we can move to a CSS-class-on-`<html>` pattern with an inline detection script (same approach as the bilingual-locale gating already in the docs home).

### Misc

- `API_VERSION` literal bumped 2.5.1 → 2.5.2 in lockstep with `pyproject.toml`.

### Verified

- Web build: green (24/24 pages).
- VitePress docs build: green.
- 5/5 i18n locales validate; `landingPage.legalDisclaimer` namespace present and aligned (5 keys × 5 locales = 25 entries).

## [2.5.1] - 2026-04-30

Round-2 audit closure — six concrete fixes across security, GDPR data-subject rights, retention, and one cosmetic. Drives the platform from "the privacy notice promised these things" to "the platform actually does them".

### 🟠 Added — `DELETE /api/v1/auth/me` (GDPR Art. 17 — right to erasure)

Pre-2.5.1 `docs/privacy.md` advertised the right to erasure but the platform offered no technical mechanism: a self-hosted deployer who received an Art. 17 request could only run raw SQL. The new endpoint:

- Re-authenticates via `current_password` (a stolen access token alone is not enough).
- Hard-deletes `users`, `memberships`, `api_keys`, `password_reset_tokens` for that user.
- **Pseudonymises** `audit_logs` rows authored by the user (null `user_id`, `ip_address` → `127.0.0.1`, `user_agent` → `[erased]`). Audit-trail integrity is the controller's legitimate interest under Art. 6(1)(f); Art. 89(1) explicitly allows pseudonymisation here.
- **Single-admin protection**: HTTP 409 if the user is the only admin of an org with other members — promote another admin first.
- **Lone-tenant cascade**: if the user is the only member of an org, the entire org and tenant data (`scans`, `findings`, `assets`, `incidents`, `vendors`, `business_processes`, `scan_schedules`, `scan_results`, `api_keys`, `memberships`, `audit_logs`) are deleted.
- **Session revocation**: current refresh token added to `revoked_tokens` with reason `"erasure"`.

### 🟠 Added — `GET /api/v1/auth/me/export` (GDPR Art. 20 — data portability)

Returns a structured JSON document with the data subject's personal data: `profile`, `memberships` (joined to `organizations`), `api_keys` (metadata only — raw secrets are shown once at creation), `audit_logs` authored by the user, plus a `_meta` section with schema version + scope explanation.

**Scope is deliberately personal data only.** Tenant data (scans, findings, assets, incidents, vendors, BIA processes) belongs to each organisation's controller, not to the user — excluded to stop Art. 20 from becoming a covert tenant-data-exfil channel.

### 🟠 Added — `cleanup_expired_auth_records` Celery beat task (GDPR Art. 5(1)(e))

Pre-2.5.1 `revoked_tokens` and `password_reset_tokens` model files documented "a periodic Celery task can prune", but no such task existed. Both tables grew indefinitely. The new task `app.tasks.cleanup_tasks.cleanup_expired_auth_records` runs hourly and prunes both tables `WHERE expires_at < now()`. Idempotent.

### 🟠 Hardened — `setup_row_level_security` refuses to start in production with a SUPERUSER app role

Pre-2.5.1 the app logged a WARNING and continued when the Postgres role had `rolsuper=true` or `rolbypassrls=true`. The default `postgres:16-alpine` image creates `POSTGRES_USER` as SUPERUSER → a vanilla `make prod` deploy ran with decorative RLS, and a future bug dropping `WHERE organization_id` would silently exfiltrate everyone.

Now the warning becomes a hard error if `settings.environment == "production"` AND `RLS_SUPERUSER_OK=1` is not set. The escape hatch is intentionally explicit; the Makefile's `prod-preflight` prints a red banner when the flag is set so operators can't set-and-forget. In `dev` / `test` the WARNING-only behaviour is preserved.

### Fixed — `API_VERSION` literal lagged behind the package version

`packages/api/app/main.py:24` was hardcoded `"2.4.26"` — every release-bump for three patch versions left it stale, polluting `/openapi.json` and the startup audit log. Now `"2.5.1"` with a comment about the lockstep with `pyproject.toml`. The matching test now asserts equality with `app.main.API_VERSION` so future bumps don't break it.

### Fixed — Footer copyright on the docs landing

`docs/.vitepress/theme/components/Home.vue` still rendered `© 2024–2026 Fabrizio Salmi · This is not legal advice` in EN+IT. v2.5.0 fixed the **app** landing footer but missed the **docs** landing footer. Both now render `© 2026 Salmi Fabrizio — VAT IT 03072120995 — Via Sapri 9, 16134 Genova` per Art. 7-12 D.Lgs 70/2003. Privacy and Terms links added to the docs footer for parity with the app footer.

### Verified

- API tests in Docker: **187 passed, 62 skipped, 0 failed**.
- Web build: green (24/24 pages).
- Python `ast.parse` clean on every edited module.

## [2.5.0] - 2026-04-30

**Legal-review hardening release. Minor-version bump because git history is rewritten — every fork and existing clone of this repo must rebase / re-pull.**

### 🔴 Removed — Real Italian organisations from the demo seed (defamation / GDPR risk)

Pre-2.5.0 `scripts/seed_demo.py` shipped with **ten real Italian organisations** (a hospital, a bank, an energy distributor, a transport operator, a municipality, a water utility, three private companies, a telco) — names, real public FQDNs, real IP addresses — together with **simulated vulnerability findings** ("TLS 1.0 attivo sul portale pazienti", "SCADA esposto su internet", "RDP password default", "porta MySQL esposta", etc.). The repo is public and AGPL.

That is a clean **diffamazione Art. 595 c.p.** + **danno reputazionale Art. 2043 c.c.** exposure against ten identifiable third parties — most of them NIS2 *essential entities* in regulated sectors. Aggravated for the healthcare entry, which referenced HIS / PACS systems (Art. 9 GDPR sensitive-category data), and creates a residual Art. 615-quater / 615-quinquies c.p. surface (publishing apparent vulnerability metadata against real public FQDNs is exactly the heat-map pattern those articles target — even where the findings are wholly fabricated, the underlying assets are real and reachable).

**v2.5.0 fix:**
- All 10 names replaced with alphabetic placeholders (Alpha Medical, Beta Bank, Gamma Power, Delta Foods, Epsilon Telco, Zeta Rail, Demoville City Council, Eta Water Utility, Theta Consulting, Iota Confectionery).
- All ~40 FQDNs migrated to the IANA-reserved `.example` TLD (RFC 2606) — guaranteed never to resolve to a real production host.
- All public IP addresses migrated to the IANA documentation blocks 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (RFC 5737) — guaranteed never to be routed.
- Private CIDRs already on RFC 1918 ranges, unchanged.
- Admin email pattern `fab@<real-domain>` replaced with `admin@<placeholder>.example`.
- Demo password changed from a memorable-name seed to `demo-only-do-not-deploy` to flag intent.
- File header carries an explicit legal note documenting the change and the historical context.

**`git filter-repo` — history rewrite, force-push:**

The sanitisation above only fixes the working tree. Anyone who clones the repo at a v2.4.x tag or earlier still pulls a copy of `seed_demo.py` containing the real names. We therefore ran `git filter-repo --replace-text` across the entire reachable history, replacing every real name and FQDN with the corresponding placeholder, and force-pushed the rewritten branch + retagged every release. This is destructive: every fork, mirror, and existing clone must rebase or re-clone. The privacy/legal benefit outweighs the operational cost, on explicit maintainer instruction.

What this **doesn't** clean up: web archives (Wayback Machine, archive.today), RSS-feed readers that snapshotted the raw release notes, downstream forks that have not yet rebased. We accept this residual exposure — it is bounded and decreasing over time, vs. the unbounded liability of leaving the names in HEAD.

### 🟠 Added — `docs/privacy.md` (GDPR Art. 13 information notice)

Public-website privacy notice covering the documentation surface (`fabriziosalmi.github.io/nis2-public/`) and direct contact via the maintainer's email. Covers controller identity, processing purposes, legal basis, retention, recipients, transfers, data-subject rights (Art. 15-22), breach notification, and a self-hosted-deployment section that explicitly establishes the deployer as the sole data controller — no Art. 28 contract is offered or implied. Designed as a **template** that operators of self-hosted instances can adapt; the maintainer-operated portion is a parallel use of the same document.

Three honest disclosures the notice carries:

1. **Zero analytics on the documentation site** — no Google Analytics / Plausible / Matomo / Fathom / etc. Confirmed by `grep -rE "google-analytics|gtag|plausible|matomo|hotjar|amplitude|posthog|umami"` on the docs source: only false positives from VitePress dev-tools-API source (an internal Vue inspector pattern).
2. **`localStorage.nis2-doc-locale`** is the single key set by the bilingual home for the user's chosen language. It is technically necessary under the Art. 122 D.Lgs 196/2003 exemption, so no consent banner is required (and none is shipped).
3. **GitHub + Gmail are the two third-party processors** the maintainer-operated surface relies on (hosting + email). Both are named explicitly with the legal basis and the trans-Atlantic-transfer mechanism (SCC + supplementary measures per Schrems II).

### 🟠 Added — `docs/terms.md` (Art. 7-12 D.Lgs 70/2003 e-commerce decree compliance)

Operator-identification notice + Terms of Use for the documentation site and the public repo. Covers AGPL-3.0 license terms, the explicit warranty disclaimer (AGPL §15-16), a section that breaks any "the dashboard said I was compliant" downstream claim by spelling out that scores / checklists / generated PDFs are **technical aids, not legal or compliance advice**, an acceptable-use clause, the demo-data fictional-by-design clause, third-party limitation, limitation of liability, governing-law and jurisdiction (Italian Republic, Tribunale di Genova).

### 🟠 Added — Operator identification across the codebase

Per Art. 7-12 D.Lgs 70/2003 (Italian e-commerce decree, transposing 2000/31/EC), a website offering paid services must publish operator identification at every page. v2.5.0 adds this in three places:

1. **README** has a new *Legal & contact information* section: `Salmi Fabrizio` — sole proprietor — Via Sapri 9, 16134 Genova — VAT IT 03072120995 — ATECO 62.10.00 — *Regime semplificato* — `fabrizio.salmi@gmail.com`.
2. **App landing page footer** (`/`) — copyright line carries the same legal triple (operator + VAT + address) in all 5 locales.
3. **Footer column** (`Platform` group) gains explicit `Privacy` and `Terms` links pointing to the canonical `docs/privacy.md` and `docs/terms.md` on GitHub. Reachable from every page of the marketing surface.

The C.F. (codice fiscale), INPS matricola, and date of activity start are **deliberately not published** — they are not required by Art. 7-12 (which asks for operator name, address, VAT, contact) and publishing them would expand the personal-data surface without legal benefit.

### 🟠 Added — *"This is an educational heuristic, not the ACN framework"* disclaimer

The 30-item Art. 21 governance checklist + 10-row matrix sit somewhere between "didactic heuristic" and "compliance verdict", and the platform UI did not say which. External review correctly flagged that this gap could be the basis of a "but the dashboard said I was compliant" claim from a downstream user who treated the score as a regulatory deliverable.

Now the dashboard's `/dashboard/compliance` page renders an explicit warning card under the matrix:

> **Educational heuristic, not the ACN framework.** The 30-item governance checklist and this 10-row matrix are a community-curated educational heuristic mapped to the ten Art. 21(2) sub-paragraphs at a high level. They are not a verbatim reproduction of the official ACN framework (NIST-derived, detailed across Determinazioni 127434/2026 and follow-ups). For any production compliance posture, refer directly to ACN guidance and engage a qualified advisor.

The same disclaimer appears in the README as a dedicated section, and the new `docs/terms.md` codifies it into the legal-binding text. The yellow-on-yellow visual treatment is deliberate — the user has to scroll past it on every visit to the compliance page, which is the cheapest possible mitigation against downstream reliance.

Translated and surfaced in all 5 locales (en/it/fr/de/es). 25 new i18n keys, parity verified — total i18n key count rises from 782 to 807.

### 🟢 Note — copyright header year clean-up

Pre-2.5.0 the public-facing copyright lines in the app/docs footers carried `© 2024–2026 Fabrizio Salmi · This is not legal advice.`, while the source-file headers had been migrated to `2026` only in v2.4.27 (matching the project's actual first commit on 2026-04-26). v2.5.0 closes that residual: the public footer copyright now reads `© 2026 Salmi Fabrizio` and is wrapped with the operator triple (VAT + address) in line with Art. 7-12 D.Lgs 70/2003.

### Verified

- `seed_demo.py`: zero residues for any of the 10 real entity names or their domains (verified by exhaustive case-insensitive grep across `alpha-medical`, `beta-bank`, `gamma-power`, `delta-foods`, `epsilon-telco`, `zeta-rail`, `demoville.example`, `eta-water.example`, `theta-consulting.example`, `iota-confectionery`, `iota-confectionery` and the company-name prefixes).
- Python syntax of `seed_demo.py` validates (`python3 -m py_compile`).
- All 5 i18n locales validate as JSON; key parity 5/5; total 807 keys (was 782).
- Web build green (24/24 pages).
- `git filter-repo` rewrite preserves commit graph topology except for the substring substitutions in the affected files; tags re-pointed to the new SHAs.

## [2.4.30] - 2026-04-30

Tier-2 UI fixes from the same external review that drove v2.4.28 — five concrete bugs across the compliance page, scan-detail page, sidebar, dashboard landing, and one console warning.

### Fixed — Compliance page rendered Italian titles + English descriptions regardless of locale (Bug #1)

`/dashboard/compliance` had a hardcoded `ART21_SECTIONS` map with Italian `title` and English `description`. The comment claimed it was "by design" — keep the Italian text as the canonical legal reference. In practice it produced the worst of both worlds: an English user saw an Italian title (legible but jarring), an Italian user saw an English description (illegible to most). Same anti-pattern in the scan-detail page (`item.description` from the backend, always English).

Fix: 50 new translation strings in `compliancePage.art21Sections.{a..j}.{title,description}` across all 5 locales (en/it/fr/de/es). Both the compliance matrix page and the scan-detail compliance list now resolve `title` + `description` via `useTranslations("compliancePage.art21Sections")`. Italian sub-paragraph titles match D.Lgs 138/2024 wording; English titles match the EU Directive 2022/2555 phrasing; the other three locales follow standard EU translations.

### Fixed — Compliance page in dark mode rendered washed-out grey cards instead of red/yellow/green (Bug #2)

The `statusConfig` map used `bg-green-50 / bg-yellow-50 / bg-red-50 / bg-gray-50` with no `dark:` variants. On dark theme the `-50` shades collapsed to near-white text-on-near-black surfaces, with poor contrast and no clear status differentiation. Now each status carries a `dark:bg-X-950/40 dark:border-X-900` pair (and `dark:text-X-400` for the icon colour). Visual diff against the dashboard light/dark themes confirms the four states are immediately distinguishable on dark.

### Fixed — Scan-detail compliance row used `<span class="flex …>` (Bug #3)

The letter badge in the scan-detail compliance matrix was rendered as `<span>` with `display: flex` Tailwind utilities. `<span>` is inline-by-default; forcing flex on it works but is semantically wrong (the element is acting as a block-level container with row layout). Reviewer flagged it. Now `<div>`. Same patch refactored the inline matrix into a dedicated `ComplianceMatrixList` component that also wires the row title to the new `art21Sections` i18n namespace — so a switch from EN to IT now updates the matrix titles in both `/dashboard/compliance` and `/dashboard/scans/[id]` consistently.

### Fixed — Collapsed desktop sidebar could not be re-expanded without a page reload (Bug #4)

`/dashboard` sidebar has a chevron-left button to collapse and a chevron-right button to expand. The expand button is `<Button class="absolute -right-3 top-20 z-10 …">`. Pre-2.4.30 the parent `<aside>` had no `position: relative`, so the absolute button hunted up the DOM tree for the first positioned ancestor — which was nothing inside the dashboard layout — and ended up positioned relative to `<html>`. Combined with the dashboard layout's `flex h-screen overflow-hidden`, the button rendered ~12px past the viewport's right edge, invisible AND unreachable. Only recovery was a page refresh, which reset `collapsed` state.

Fix: added `relative` to the desktop `<aside>` so the button anchors to the sidebar's right border with the intended -12px overhang. Verified via Playwright: `getBoundingClientRect()` reports `{x:51, y:80, w:24, h:24}` post-collapse, and a programmatic click successfully re-expands the sidebar.

### Fixed — Dashboard landing 404'd on `/screenshot.png` (Bug #5)

The new public landing page at `/` (added in v2.4.27) references `/screenshot.png` for the product preview. The file shipped in `docs/public/` (used by VitePress) but not in `packages/web/public/` (Next.js). First console error on every visit to `/` was a 404 on the asset. Copied `screenshot.png` into the Next.js public directory.

### Fixed — `Received an empty string for a boolean attribute` console warning on dashboard pages

The mobile sidebar drawer used `{...(!mobileOpen ? { inert: "" as unknown as boolean } : {})}` to bridge the React 18 / React 19 typings on the `inert` attribute. React 19 supports `inert` as a native boolean prop, and an empty string is no longer a valid stand-in. Now `inert={!mobileOpen}` directly. Console audit confirms the warning is gone.

### Misc

- Made the postgres host port configurable in `docker-compose.dev.yml`: `${POSTGRES_HOST_PORT:-5433}:5432`. Prevents collisions with other local Postgres instances on the same dev machine without forcing a compose-file edit. Default unchanged (5433).
- Fixed a stray `https://github.com/fabriziosalmi/messages` typo in the copyright header of `packages/web/src/app/dashboard/scans/[id]/page.tsx` (correct: `nis2-public`).

### Verified

- 5/5 i18n locales validate; 50 new `art21Sections` keys present and consistent across en/it/fr/de/es.
- Web build green (24/24 pages); compliance page renders correctly in 4 combinations (light/dark × en/it).
- Sidebar collapse + re-expand round-trip works without page reload (Playwright-verified).
- Dashboard public-pages console audit: zero errors after the screenshot.png + `inert` fixes.

## [2.4.29] - 2026-04-30

Privacy hygiene patch — soft mitigation, no history rewrite.

### Changed — third-party reviewer attribution: full-name+initial → first-name only

The codebase carried ~18 mentions of an external reviewer attributed by first name + last-initial (the form `Davide F.`) across source comments, the Makefile, both compose files, the i18n module, the scan-create page, the providers shell, an API router, and several CHANGELOG entries from older releases. The reviewer contributed via private email/messaging (not via a public GitHub Issue or PR), and the pattern `<common-first-name> + last-initial + project-specific context` is enough to make the person reasonably identifiable under GDPR Art. 4(1) — and we never sought explicit consent to attribute publicly.

Fix: `sed`-replace `Davide F.` → `Davide` across every tracked file (also tidied one historical `Davide Foresti (Essedieffe)` mention to `Davide` for consistency). A common Italian first name on its own (no surname, no initial) is not, in isolation, reasonably identifying — it functions like a generic credit ("flagged by Davide") without uniquely picking out a real person from the project context. The reviewer is aware they were credited, so this is a soft mitigation rather than full anonymisation.

What is **not** done in this patch (deliberate):

- **No `git filter-repo` / history rewrite.** Older commit messages and the v2.4.27 / v2.4.28 release notes on GitHub still contain `Davide F.` (those are pushed and clones are in the wild). Rewriting tagged history on a public repo would force every fork and clone to rebase, would break the cosign / SHA references in any downstream pipeline, and the data is in any case already mirrored to the Wayback Machine and any RSS reader that subscribed to the releases feed. The marginal privacy gain doesn't justify the operational cost.
- **No anonymisation of the reviewer's actual professional context** (the `Reported by …` lines retain their technical context — Windows host, WSL2, `make prod`, etc — because that context is what makes the bug-report comment useful for a future maintainer trying to reproduce or understand the fix).

The two GitHub release notes (v2.4.27, v2.4.28) are edited in-place via `gh release edit` to drop the `Davide F.` mentions there as well — those *are* mutable on GitHub's side without rewriting git history.

### Documentation note for future contributions

For private-channel feedback (email / Slack / etc) we will from now on either ask the reporter explicitly if they want to be credited by name or default to first-name-only. Public GitHub Issues and PRs are different — a public submission is itself an act of public contribution, and crediting the GitHub handle is the de-facto OSS norm.

## [2.4.28] - 2026-04-30

External-review triage release. Three issues flagged by Davide on the v2.4.27 build, all real, all fixed in this patch.

### Fixed — Compliance matrix subtitle pointed at the wrong article of D.Lgs 138/2024

The subtitle of the Compliance Matrix page (and the demo seed's `compliance_article` field) read `"Art. 21 D.Lgs 138/2024 — Cybersecurity risk management measures"` in all 5 locales. **This is wrong**: in Italy's NIS2 transposition (D.Lgs 138/2024) the ten risk-management measures sit at **Art. 24, comma 2**, lettere a–j; "Art. 21" is the corresponding article of the EU Directive 2022/2555 that the decree transposes. Conflating the two is the kind of mistake that immediately tells an Italian compliance reviewer the platform doesn't actually know the local legal landscape.

Now: `Art. 24(2) D.Lgs 138/2024 (recepimento Art. 21 NIS2) — …` (and the locale-appropriate verb: *transposes* / *recepimento* / *transposition* / *Umsetzung* / *transposición*). The subtitle now disambiguates: tells you the Italian-law citation AND the EU-directive origin in one breath. Also updated `scripts/seed_demo.py` so demo data carries the correct citation.

The other "Art. 21" mentions across the codebase (e.g. `compliancePage.complianceMatrixTitle = "NIS2 Compliance Matrix Art. 21"`, `landingPage` references) are correct as-is — they refer to Art. 21 of the *Directive*, not of the decree.

### Fixed — `make clean-all` failed silently on Windows hosts without a real Python install

`make clean-all` and `make clean` invoke `python scripts/clean.py`. On a Windows host that doesn't have a real Python install, the bare `python` resolves to the Microsoft Store stub at `%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe` — which exits 9009 with a localised "Python non trovato" message and the make target fails before `clean.py` can run. Reported by Davide

The Makefile now does cross-platform Python detection:

```makefile
ifeq ($(OS),Windows_NT)
  PYTHON := $(firstword $(shell where py 2>nul) $(shell where python3 2>nul) $(shell where python 2>nul))
else
  PYTHON := $(firstword $(shell command -v python3 ...) $(shell command -v python ...))
endif
```

Detection priority is `python3` → `py` (Windows launcher, only present with a real install — finding it is itself a positive signal Python is genuinely available) → `python` (last-resort, may still be the Store stub on Windows but on Unix it's typically real). The `clean`, `clean-all`, `test-api`, and `test-scanner` targets now gate on `$(strip $(PYTHON))` and emit a multi-line error pointing at python.org and at Settings → Apps → Apps & Features → App execution aliases (where the Store stub is toggled off) when nothing is found.

### Fixed — `make prod` exited with generic "container is unhealthy" when `.env` was incomplete

A common first-run failure: operator copies `.env.example` to `.env` but forgets to fill `POSTGRES_PASSWORD` / `JWT_SECRET` / `CORS_ORIGINS`. Postgres refuses to initialise without a password, exits, Caddy's `depends_on: api: service_healthy` chain breaks, and Docker Compose surfaces a generic `dependency failed to start: container docker-postgres-1 is unhealthy`. The actual root cause is buried in `docker logs docker-postgres-1` ("Database is uninitialized and superuser password is not specified") — operators rarely look there first. Reported by Davide

Added a `prod-preflight` target that runs before `prod-up`. It validates:

1. `.env` file exists (otherwise: prints the exact `cp .env.example .env` command and the list of variables to set).
2. `POSTGRES_PASSWORD` is non-empty.
3. `JWT_SECRET` is not the placeholder `GENERATE_ME...` from `.env.example`.
4. `JWT_SECRET` is at least 32 characters (the same minimum the API enforces in `app/config.py`).
5. `CORS_ORIGINS` is non-empty.

Each failure prints a self-contained, actionable error (the exact command to fix, e.g. `openssl rand -base64 32`) and exits 1 before any container is created. Operator now sees the real problem in 5 seconds instead of 5 minutes of `docker logs` archaeology.

### Verified

- 5/5 i18n locales validate as JSON, all 782 keys aligned, Art. 24(2) citation is consistent across en/it/fr/de/es with locale-appropriate verbs (`transposes` / `recepimento` / `transposition` / `Umsetzung` / `transposición`).
- `make prod-preflight` smoke-tested against three scenarios: missing `.env` (fails with cp instruction), empty `POSTGRES_PASSWORD` (fails with postgres-specific message), `JWT_SECRET=GENERATE_ME` placeholder (fails with `openssl rand` instruction), valid `.env` (passes with `.env preflight: OK`).
- `make -n clean / clean-all / test-api / test-scanner` correctly resolve `$(PYTHON)` on macOS (`python3`) — Windows-side detection unchanged in shape, exercises the same `where py` / `where python` chain that worked on Davide's repro path before the Store-stub trap.

## [2.4.27] - 2026-04-30

Public landing page + multi-locale wiring, three audit fixes (frontend silent-catch, prod web healthcheck, RLS hardening), and assorted cleanup. Triggered by a request to "find blocker problems and fix all" before turning attention to UX.

### What changed at a glance

- **Public landing page on `/`** (replaces the `Loading…` redirect-spinner). Hero, six-card feature grid mapped to actual API router families, product screenshot in a mac-chrome frame, three-step `make dev` onboarding, four-audience block (CISO / DPO / Consultant / IT), self-hosted commitment section with tech-stack pills, gradient final CTA, and a four-column footer.
- **Authenticated users still land on `/dashboard`** via the same client-side redirect. The visible delta is for unauthenticated visitors only.
- **Landing page is fully i18n-wired** in en / it / fr / de / es. `Accept-Language` negotiation already worked for the rest of the app via `i18n.ts`; the landing now participates in it. ~94 new keys under `landingPage.*`, parity verified across all 5 locales.
- **`pt` removed from the `LanguageSwitcher`** — `messages/pt.json` does not ship, so picking "Português" wrote a cookie that the negotiator (correctly) rejected, and the UI snapped back to English. Switcher and negotiator are now in lockstep.
- **Italian copy review on the landing**: 17 anglicism-or-literal-translation tweaks (e.g. "a un terzo" → "a terze parti", "tracking di owner" → "tracciamento di responsabile", "Self-host della piattaforma" → "Avvia la piattaforma in self-hosting", "sub-paragrafo dell'Art. 21" → "lettera dell'Art. 21"). Anglicisms accepted in the GRC-IT register stay (`workspace`, `finding`, `policy`, `compliance`, `Red Button`, `Early Warning`, `air-gapped`).

### Fixed — Settings pages no longer silently overwrite saved settings (BLOCKER)

`/dashboard/settings/scan-defaults` and `/dashboard/settings/organization` both did `api.getOrg(orgId).then(reset).catch(() => {})`. On load failure (network blip, transient 401 before refresh, RLS misconfig) the swallow:

- **scan-defaults**: rendered the hardcoded `defaults` constant and a Save click PATCH'd those defaults over the org's actual saved settings. Unrecoverable data loss disguised as a successful save toast.
- **organization**: rendered an empty form name field plus blank disabled slug / plan / orgId fields with no toast or error explaining why.

Both now surface a `loadFailed` error banner with a `retry` button, disable Save until the load succeeds, and propagate the underlying API error message to the user. New `loadFailed` and `retry` keys in the `organizationPage` and `scanDefaultsPage` namespaces of all 5 locales (10 new keys total).

### Fixed — Web service has a healthcheck in prod (BLOCKER)

`infra/docker/docker-compose.prod.yml` had Caddy gated on `web: { condition: service_started }`, which Docker considers green the moment the container's ENTRYPOINT process is running — NOT once it's accepting connections. Next.js standalone has a measurable warm-up window where `node server.js` is alive but the listen socket is not yet open; Caddy started proxying immediately and the first user requests after `make prod` got 502s for ~5–15s.

Fix: a `node`-based healthcheck (`require('http').get('http://127.0.0.1:3000/', ...)`) that returns 0 on any 2xx/3xx/4xx and 1 on 5xx or connection error. Caddy's dependency on `web` is now `service_healthy`, mirroring the existing gate on `api: { condition: service_healthy }`.

### Fixed — Cron `_should_run` no longer swallows exceptions silently (SERIOUS)

`app/tasks/scan_tasks.py:_should_run` wrapped the entire matcher in `try / except: return False`. v2.4.26 added input validation at route level so new schedules cannot persist a bad expression, but legacy rows that pre-date the validator (e.g. `@daily`, day names like `MON`) would still fall into this branch and the schedule simply never fired — operators had no signal as to why. Now the except branch logs at WARNING with the offending expression. Stays at WARNING (not ERROR) because beat iterates every minute over every schedule; ERROR would spam the log if a single bad row exists.

### Hardened — RLS policy now has explicit `WITH CHECK` + superuser warning at startup

`app/database.py::setup_row_level_security` previously created the policy with only `USING (...)`. Postgres treats a missing `WITH CHECK` as "same as USING" for INSERT / UPDATE — which happened to be safe here, but was implicit and brittle. Making `WITH CHECK` explicit pins the contract: every INSERT and UPDATE must match the current org, so a misconfigured task cannot smuggle a row with a foreign `organization_id` even if the SELECT side were ever loosened.

Defense-in-depth check on lifespan startup: if the DB role the API connects with has `rolsuper=t` or `rolbypassrls=t`, log a WARNING. The default `postgres:16-alpine` image creates `POSTGRES_USER` as a SUPERUSER, which silently bypasses every RLS policy regardless of `FORCE ROW LEVEL SECURITY`. Operators going to production should provision a non-superuser app role with BYPASSRLS revoked; this surface line tells them why and how. Not a hard-fail (would break first-run UX), just a loud signal.

### Docs site — bilingual home (EN + IT) at design parity with the dashboard landing

The docs site at `https://fabriziosalmi.github.io/nis2-public/` used to render the VitePress default home (Hero + Features grid). After the dashboard app got a real landing page in this same release, the docs page felt clearly behind: a generic VitePress hero next to a curated product page made the platform look unprofessional to anyone visiting both. Closed by porting the dashboard landing to a VitePress-native Vue component, with two adjustments:

- **Bilingual EN + IT, zero-flash detection.** The DOM contains both languages paired through `<span class="locale-en">` / `<span class="locale-it">`. An inline detect script in `<head>` (~280 chars, sync, pre-paint) reads `localStorage.nis2-doc-locale` and falls through to `navigator.language`, then writes `class="locale-en"` or `class="locale-it"` on `<html>` BEFORE first paint. CSS hides the inactive language. An IT visitor never sees an English flash, and vice versa. A small `EN | IT` toggle in the top-right lets the user override (persisted in localStorage). hreflang `en` / `it` / `x-default` declared in head so Google indexes both versions correctly. Other doc pages stay English-only — the bilingual treatment is scoped to the marketing surface.
- **CTA wiring differs from the app landing.** Where the app sends users to `/register` and `/login`, the docs landing sends them to `/guide/getting-started`, the GitHub repo, and `mailto:fabrizio.salmi@gmail.com` for consultation. A docs visitor wants to learn how to install, not provision a SaaS account.

Implementation: Tailwind v4 wired into the VitePress Vite pipeline (`@tailwindcss/vite`), custom `theme/components/Home.vue` + `Logo.vue`, registered globally via `theme/index.ts::enhanceApp`, frontmatter on `docs/index.md` switched to `layout: page` + `sidebar: false` + `aside: false` so the marketing canvas gets full width but the VitePress nav stays for site navigation.

#### Cascade-layer correction (load-bearing)

First preview rendered the home as if Tailwind weren't loaded — h1 at 16px / weight 400, padding utilities collapsed, `bg-slate-900` no-op. Root cause: `@import "tailwindcss"` (the canonical one-liner) wraps everything in `@layer theme/base/components/utilities`, but VitePress ships its global stylesheet UNLAYERED. CSS rule: anything outside `@layer` outranks anything inside `@layer`, regardless of selector specificity. So VitePress's `h1,h2,h3,...,h6 { font-size: 16px; font-weight: 400 }` reset beat Tailwind's `.text-4xl { font-size: 2.25rem }` (in `@layer utilities`) and the heading rendered at body size. Same mechanism killed `pt-20`, `bg-slate-900`, etc.

Fix: split the Tailwind import so theme + preflight stay in low-priority layers but **utilities land unlayered**, putting them at the same cascade level as VitePress and giving specificity its normal say:

```css
@layer theme, base, components, utilities;
@import "tailwindcss/theme" layer(theme);
@import "tailwindcss/preflight" layer(base);
@import "tailwindcss/utilities";  /* unlayered — beats VitePress unlayered */
```

After: h1 = 60px / weight 700, all responsive utilities (`sm:text-5xl`, `lg:text-6xl`, `pt-20`, `sm:py-24`, `bg-slate-900`, etc) apply correctly. Verified via `getComputedStyle()` on the rendered DOM and visual diff against the dashboard landing.

The dashboard app (Next.js + Tailwind v4 in webpack) was unaffected because it doesn't ship competing unlayered base styles. The collision was VitePress-specific.

Companion fixes shipped in the same change:
- `@custom-variant dark (&:where(.dark, .dark *))` — Tailwind v4's `dark:` modifier defaults to `prefers-color-scheme`; VitePress drives dark via `<html class="dark">`, so without the custom variant the topbar flipped dark while the home stayed light.
- `.docs-home a { color: inherit; text-decoration: none }` (full-specificity, not `:where()`) plus Tailwind v4 `!` prefix on CTA color utilities (`!text-white`, `!text-slate-900`) — VitePress's `a { color: var(--vp-c-brand-1) }` was beating low-specificity resets and rendering CTA buttons with invisible text on bright backgrounds.
- Explicit `line-height` on `.docs-home h1/h2/h3` (1.1 / 1.2 / 1.3) — Italian copy is markedly more verbose than English, and several headings wrap to 2-3 lines; the default Tailwind line-height made wrapped lines visually collide.

### Misc

- `next.config.ts`: pin `outputFileTracingRoot` to silence the Next 15 multi-lockfile warning ("We detected multiple lockfiles..." — caused by the docs root having its own `package-lock.json` for the VitePress build).
- Removed two stray empty escaped-paren directories `packages/web/src/app/\(auth\)` and `packages/web/src/app/\(dashboard\)` (cruft from a botched shell command, never tracked in git).
- Removed the duplicate untracked `screenshot.png` at the repo root; the docs version under `docs/public/screenshot.png` (referenced by README) is the only copy needed.
- Fixed a `t.rich` runtime error on the SelfHosted section: the `production` message used a `{cmd}` placeholder when called via `t.rich({ cmd: ... })`, which expects a `<cmd>...</cmd>` rich-text tag. Updated all 5 locales to use the tag form, so the styled `<code>` injection works.

### Audit transparency: 7 reported issues, 3 real, 4 false positives

The post-v2.4.26 audit pass turned up the usual mix. This CHANGELOG records what was actually broken vs. what was misread, so future readers don't think a phantom security bug existed and was silently dropped.

| # | Reported issue | Verdict |
|---|---|---|
| 1 | Settings pages silently swallow load errors | **Real BLOCKER**, fixed above. |
| 2 | Web service in prod has no healthcheck | **Real BLOCKER**, fixed above. |
| 3 | Cron `_should_run` swallows exceptions silently | **Real SERIOUS**, fixed above. |
| 4 | Celery tasks bypass RLS context — "cross-tenant access could leak" | **False positive.** Tasks correctly propagate `organization_id` from the queued message (read from the loaded `Scan` / `Schedule` row, not from session context). The application-layer scoping is correct; RLS would only be relevant as defense-in-depth, and that surfaces in #5. |
| 5 | RLS effectively disabled when DB role is SUPERUSER | **Real, architectural** — but not an active runtime vuln (see #4). Hardened with explicit `WITH CHECK` + startup warning, above. |
| 6 | TanStack `refetchInterval` leaks after status flip | **False positive.** v5 stops polling on `false` return; not leaking. |
| 7 | `AUTH_PUBLIC_PATHS` mis-fires on `?` paths | **False positive.** The four public auth routes are POST-with-body, never carry query strings. |
| 8 | Caddyfile missing `X-Forwarded-*` headers | **False positive.** Caddy 2 `reverse_proxy` injects them by default. |
| 9 | POSTGRES_PASSWORD has no default in prod compose | **False positive — by design.** Production refusing to boot without an explicit secret is the contract; defaulting would be a security regression. |
| 10 | "Retry-then-Save race" on settings forms | **False positive.** The audit hallucinated the symptom — `disabled={loading \|\| !isDirty \|\| !!loadError \|\| loadingInitial}` resolves to `!isDirty` after a successful retry, which is correct (don't enable Save until the user has changed something). |

### Verified

- Web build green (24/24 pages).
- API tests in Docker: **187 passed, 62 skipped**, 0 failed.
- Scanner tests: 19 passed.
- E2E HTTP smoke (logged-in cookie jar, all 21 user-facing pages): all 200, zero React-error markers in the rendered HTML.
- Multi-language live test: `/`, `/login`, `/dashboard/settings/scan-defaults` correctly localised in en / it / fr / de / es via `Accept-Language` negotiation.
- i18n parity: 5/5 files with identical key set (782 keys each), all ICU placeholders aligned, all rich-text tags balanced, no empty values.

## [2.4.26] - 2026-04-29

API surface audit triage — closes the only **real** BLOCKER from the v2.4.25 audit pass plus one verified SERIOUS gap. The other "blockers" the audit agent flagged turned out to be false positives on close reading; this CHANGELOG documents what was actually broken vs. what was misread, so the audit trail is honest.

### Audit transparency: 2 of 3 reported blockers were false positives

The audit agent that ran after v2.4.25 reported 3 BLOCKER-class issues. Verifying each against the source:

| # | Reported issue | Verdict |
|---|---|---|
| 1 | API key expiration race in `dependencies.py:297-303` — "request A proceeds with stale state" | **False positive.** The expiry check (`expires_at <= now`) is inline in the same request and raises 401 unconditionally if the key is expired. There is no window where a request "proceeds with stale state" — both concurrent requests on an expired key get rejected. The `is_active=False` flush is best-effort cleanup; even if it's rolled back, the next request still rejects via the inline expiry check. |
| 2 | Missing `await db.commit()` after `db.delete()` across multiple routers | **False positive.** `get_db` is a context-manager dependency in `app/database.py:78-107` that calls `await session.commit()` at request close (after `yield session` returns), and rolls back on exception. The routers' `db.delete() + db.flush()` pattern is correct — flush sends the DELETE to the connection so subsequent queries in the same request see it gone, and the actual COMMIT is at the dependency boundary. The agent missed `get_db`. |
| 3 | Cron expression validation no-op in `schedules.py:79-81` — accepts `"99 99 99 99 99"` | **REAL.** The route only checked field count, not field values. Bad input was accepted and the schedule silently never fired (the parser in `_should_run` swallows exceptions and returns False). Fixed in this patch. |

Only #3 was a real bug. The agent's report on the other two was based on reading the route files in isolation without tracing the request lifecycle through the dependencies and middleware. The CHANGELOG records this so a future reader doesn't think a phantom security bug existed and was silently dropped.

### Fixed — Cron expression validation (was BLOCKER #3)

Pre-2.4.26 `POST /api/v1/schedules` only checked that `cron_expression` had 5 whitespace-separated fields. Strings like `"99 99 99 99 99"`, `"a b c d e"`, or `"@daily"` were accepted, persisted, and rendered in the UI as valid schedules — but never fired, because `app.tasks.scan_tasks._should_run` silently swallows parse exceptions and returns False. Particularly painful "looks valid, doesn't work" failure mode.

**Fix**: new `app/utils/cron.py` with a `validate_cron(expr: str) -> None` function (raises `CronValidationError`, a `ValueError` subclass). Wired into `create_schedule` AND `update_schedule` (a PATCH could previously clobber a working schedule with a parse-fail string). The validator's accepted grammar is exactly the subset that `_should_run` understands — single source of truth, no acceptance/execution drift.

**Accepted forms per field**: `*`, `N`, `N-M` (range), `N,M,K` (list), `*/S`, `N-M/S` (step). Field ranges enforced: minute 0-59, hour 0-23, day-of-month 1-31, month 1-12, day-of-week 0-7. Vixie keywords (`@daily`, `@hourly`, `@reboot`) and day names (`MON`, `TUE`) are explicitly rejected — silent acceptance + runtime parse failure is the exact mode this patch closes.

**Tests**: 47 unit tests in `tests/test_cron_validator.py` covering accepted forms, field-count errors, range checks, range-form (inverted ranges, endpoint-at-boundary), step-form (zero/negative/empty), list-form (empty elements, out-of-range elements), and the rejection of Vixie keywords. The agent-flagged smoking gun (`"99 99 99 99 99"`) has its own pinned test.

### Fixed — API key scope validation (verified SERIOUS, not BLOCKER)

The `POST /api/v1/api-keys` endpoint stored `scopes` as an arbitrary list of strings without validation against any canonical vocabulary. `["yolo", "", "scan:read"]` was accepted, persisted, and returned to the UI — implying enforcement that didn't exist (no code anywhere reads `api_key.scopes` to authorise routes; that's a separate, larger behavioural change tracked for a follow-up).

**Fix**: `app/routers/api_keys.py` now defines `VALID_API_KEY_SCOPES` (frozenset of 8 `<resource>:<verb>` strings) and a `_validate_scopes` helper that rejects unknown scopes, empty / whitespace-only strings, empty lists, duplicates, and non-string elements with HTTP 400. The error message lists the allowed scopes so the UI can show a hint without an extra round-trip.

**Tests**: 15 unit tests in `tests/test_api_key_scopes.py` pinning every accepted form, every rejection class, and the vocabulary shape itself (so adding a scope is a deliberate two-line change to api_keys.py + the test, never an accident).

### Verified

- 62 new unit tests, all green (47 cron + 15 scope).
- Existing standalone tests still pass — no regressions.
- Local: `ENVIRONMENT=development pytest tests/test_target_validator.py tests/test_report_i18n.py tests/test_cron_validator.py tests/test_api_key_scopes.py` → **126 passed**.

### Deferred to v2.4.27+

- **Route-level enforcement of API key scopes** — currently scopes are validated at create/update time and stored, but no auth dependency reads them. Closing this requires deciding the per-route mapping (`/scans/*` → `scan:read`/`scan:write`, etc.) and is a behavioural change that wants its own patch with a clear migration story for existing keys.
- **Recharts colour palette tuning for deuteranopia (a11y-21)** — still a non-issue: dashboard charts use a single dark-blue series. Will revisit if multi-series charts ship.

## [2.4.25] - 2026-04-29

Closes the **second deferred item from the v2.4.23 a11y audit** — mobile sidebar focus trap (WCAG SC 2.4.3 Focus Order + 2.1.2 No Keyboard Trap).

### Fixed — keyboard focus stays inside the open mobile drawer

Pre-2.4.25 the mobile slide-out nav drawer had no focus management. Three concrete bugs:

1. **Tab spilled out of the drawer**. A keyboard user opened the drawer, tabbed to the last nav link, hit Tab once more — focus left the drawer entirely and landed on whatever element happened to be in the dim main content behind it. The drawer was a *visual* modal but not a *programmatic* one.
2. **No initial focus**. Opening the drawer didn't move focus inside it. The next Tab keystroke continued from wherever focus happened to be (typically the hamburger trigger), bypassing the drawer's links unless the user manually clicked one.
3. **No focus restoration on close**. Closing the drawer (Esc, overlay click, or nav-link click) didn't return focus to the trigger button. Keyboard users lost their place in the page.
4. **Closed drawer was still tabbable**. The slide-translated `-translate-x-full` moves the drawer offscreen visually but keeps its links in the Tab order. Pre-2.4.25 a mobile keyboard user tabbing through the main content would suddenly find focus on a link inside the invisible drawer behind the page.

### How it works

- **Two new refs in `Sidebar`**: `asideRef` (the drawer element, scope for the focus query) and `triggerRef` (the hamburger button, focus restore target).
- **Existing `useEffect` extended**: when `mobileOpen` flips to `true`, focus the first focusable element inside the drawer; install a `keydown` listener that handles Escape (close) AND Tab (wrap focus inside the drawer using the de-facto tabbable selector). On close (cleanup), the listener is removed and focus is restored to the trigger.
- **Tab wrap logic**: re-queries on every keystroke so dynamically added/removed elements (e.g. the destructive findings badge that appears when critical count > 0) participate. Shift+Tab from the first focusable wraps to the last; Tab from the last wraps to the first.
- **`inert` when closed**: React 19 supports `inert` natively as a boolean prop. We add it to the drawer when `mobileOpen=false` so the browser refuses to focus anything inside the slid-offscreen panel — eliminating bug #4.
- **Drawer marked `role="dialog"` + `aria-modal="true"`**: AT now recognise it as a modal panel; combined with the trap, screen-reader users get a proper modal-dialog announcement on open.

### Verified

- `npm run build` green — 24/24 pages compile, no new TS errors.
- Manual keyboard smoke: open hamburger via Enter, focus lands on first nav link, Tab walks down to "Logout", Tab once more wraps back to the first link, Shift+Tab from first link wraps to "Logout", Esc closes the drawer and focus returns to the hamburger trigger.
- With drawer closed, Tabbing through the main content never touches drawer-internal elements (verified by inspecting `document.activeElement` across a full Tab cycle).

### Deferred

- Recharts colour palette tuning for deuteranopia (a11y-21) — currently a non-issue: the dashboard charts use a single dark-blue series with no per-bar palette where deuteranopia matters. Will revisit if multi-series charts are added.

## [2.4.24] - 2026-04-29

Closes the **first deferred item from the v2.4.23 a11y audit** — per-page `<title>` (a11y-11 / WCAG SC 2.4.2 Page Titled).

### Fixed — every page now has its own `<title>`

Pre-v2.4.24 every browser tab said "NIS2 Platform" — the only metadata exported was the root layout default. That fails three real workflows:

1. **Bookmarking**: a user bookmarking `/dashboard/findings` got a "NIS2 Platform" entry, indistinguishable from a bookmark of `/dashboard/scans` or `/login`.
2. **Tab management**: power users with 5–10 tabs across the platform couldn't tell tabs apart at a glance — every tab title and favicon was identical.
3. **Screen-reader announcement (WCAG SC 2.4.2)**: SR users hear the page title when a page loads. With every page sharing one title, the announcement carried zero information about *where* they had landed.

### How it works

A new `useDocumentTitle(title)` hook (`src/hooks/use-document-title.ts`) mutates `document.title` in a `useEffect` and restores the previous title on unmount. Every page-level component now calls it with its localised `t("title")` from the existing `useTranslations` namespace — so an Italian user on `/dashboard/scans` sees "Scansioni — NIS2 Platform" in the browser tab.

**Why a hook and not `generateMetadata`**: the App Router exposes per-route metadata only from server components. The dashboard pages are all `"use client"` because they pull from TanStack Query / Zustand stores that need browser-only APIs. Splitting each route into a server-shell + client-body is a 22-route refactor for no incremental benefit — `useEffect` is the idiomatic React pattern for this case.

### Coverage

22 page-level components wired in this patch:

- **Auth**: `/login`, `/register`, `/forgot-password`, `/reset-password`
- **Dashboard root**: `/dashboard`
- **Dashboard primary**: `/dashboard/scans`, `/dashboard/scans/[id]` (uses scan name when loaded), `/dashboard/scans/new`, `/dashboard/scans/schedules`, `/dashboard/scans/[id]/compare`, `/dashboard/findings`, `/dashboard/assets`, `/dashboard/compliance`, `/dashboard/reports`
- **Settings**: `/dashboard/settings` (root index), `/dashboard/settings/profile`, `/dashboard/settings/organization`, `/dashboard/settings/team`, `/dashboard/settings/api-keys`, `/dashboard/settings/notifications`, `/dashboard/settings/audit-log`, `/dashboard/settings/scan-defaults`

Each title is fully localised across all 5 locales (en / it / fr / de / es) — no new translation keys were added; the patch reuses the existing `t("title")` strings already maintained by every namespace.

### Verified

- `npm run build` green — 24/24 pages compile, no new TS errors.
- Manual smoke: navigating between /dashboard, /dashboard/scans, /dashboard/findings, /login each updates the browser tab title to the localised page name + " — NIS2 Platform" suffix.
- /dashboard/scans/[id] picks up the actual scan name once the scan hydrates (`scan?.name || ts("title")` fallback so the tab isn't blank during the loading window).

### Deferred to v2.4.25

- Mobile sidebar focus trap (Sheet/Drawer refactor).
- Recharts colour palette tuning for deuteranopia (a11y-21).

## [2.4.23] - 2026-04-28

Dedicated **WCAG 2.1 Level AA accessibility audit** of the entire frontend. A draconian sweep across every authenticated screen identified 30 a11y gaps — the patch closes the highest-impact 20 of them in one pass, covering keyboard users, screen-reader users, and users with colour-vision deficiencies.

### Added — `a11y` i18n namespace

A new `a11y` namespace in all 5 locales (en/it/fr/de/es) holds accessibility-only strings (skip-link copy, button names for icon-only triggers, dynamic state labels). Localised so a Spanish keyboard user hears "Saltar al contenido principal", not "Skip to main content".

### Fixed — Tier 1 (keyboard + screen-reader navigation)

- **a11y-10 (WCAG SC 2.4.1 Bypass Blocks)**: skip-to-content link is now the first focusable element on every dashboard page (`sr-only focus:not-sr-only`), letting keyboard users jump past the 17-link sidebar straight to `<main>`.
- **a11y-08 (SC 4.1.3 Status Messages)**: dashboard loading + redirect splashes get `role="status" aria-live="polite"` so SR users hear "Loading…" / "Redirecting…" instead of silence.
- **a11y-01 (SC 4.1.3)**: dedicated polite live-region next to the sidebar nav announces critical-finding count changes — the destructive pill on "Findings" is no longer purely visual.
- **a11y-02 / a11y-09 / a11y-15 (SC 4.1.2 Name, Role, Value)**: the Theme toggle, Language switcher, and user-menu trigger were icon-only buttons whose `aria-label` was hardcoded English. Now localised AND surface the current state ("Theme: dark", "Language: Italian", "Open user menu for Jane Doe") so SR users know what activating the button will offer.
- **a11y-13 (SC 3.3.2 Labels or Instructions)**: filter Selects on /findings used a placeholder for their label, which disappears once a value is picked. Each Select now has a stable `aria-label`.
- **a11y-04 / a11y-17 (SC 4.1.2)**: select-all and per-row checkboxes on the findings table now have `aria-label` describing what they toggle ("Select row: TLS certificate expired on…").
- **a11y-18 (SC 2.1.1 Keyboard)**: the chevron column on the findings table is now a real `<button>` with `aria-expanded`, so keyboard users can toggle the per-row detail expansion. Previously the row was clickable but had no keyboard equivalent.
- **a11y-19 (SC 2.4.4 / 2.4.8)**: header breadcrumbs are now an `<ol>` with `aria-label="Breadcrumb"`, the active crumb has `aria-current="page"`, and the chevron separators are `aria-hidden`. Sidebar nav links also surface `aria-current="page"` for the active route.
- **a11y-20 (SC 2.1.2 No Keyboard Trap)**: the mobile sidebar drawer now closes on Esc — previously a keyboard user had to tab to the dim overlay and Enter to dismiss it. Mobile menu trigger also surfaces `aria-expanded` + `aria-controls`.

### Fixed — Tier 2 (perception + low-vision support)

- **a11y-05 (SC 1.4.1 Use of Color)**: the compliance score (good/fair/poor) used to be communicated *only* through green/yellow/red text colour — fails for users with deuteranopia/protanopia and on greyscale prints. Dashboard score now ships an icon prefix (`✓` / `⚠` / `✗`) plus an `aria-label` that names the band ("75 (good)"). All four score-display callsites in /dashboard, /scans, /reports and /scans/[id] surface the band via `aria-label`.
- **a11y-14 (SC 3.3.1 Error Identification + 1.3.1 Info & Relationships)**: login + register form fields with validation errors now wire `aria-invalid` + `aria-describedby` so SR users hear the inline error when they refocus the offending input. Previously the styled `<p>` next to the input was visually-only.
- **a11y-16 (SC 1.1.1 Non-text Content)**: dashboard charts (bar + line) gained a `role="img"` wrapper with `aria-label`, plus a `class="sr-only"` data table fallback so SR users can read the actual values — Recharts SVG previously exposed nothing to AT.
- Decorative lucide icons inside labelled buttons (sidebar nav, theme toggle, language switcher, header user-menu, findings filter chevron, login/register loaders, expand/collapse chevrons) all now carry `aria-hidden="true"` so SR users don't hear "right-pointing chevron" between every breadcrumb.

### Added — translations

Three new `nav` keys + a 13-key `a11y` namespace in **5 languages** (en / it / fr / de / es): `skipToContent`, `themeToggle`, `languageSwitcher`, `openNavigation`, `closeNavigation`, `expandSidebar`, `collapseSidebar`, `breadcrumb`, `userMenu`, `selectAllRows`, `selectRow`, `expandRow`, `collapseRow`, plus `nav.primary`, `nav.settings`, `nav.criticalCountAnnouncement` (with proper ICU plural forms for the count).

### Verified

- All 5 locale files parse cleanly, key parity (0 missing / 0 extra across IT/FR/DE/ES vs EN).
- `npm run build` green — 24/24 pages compile, no new TS errors introduced.
- Manual keyboard-only smoke: skip-link works, Esc dismisses mobile drawer, chevron toggles row expansion, Tab order is preserved on every modified screen.

### Deferred to v2.4.24

- Per-page metadata titles via `generateMetadata` (a11y-11) — requires server-component refactor on most dashboard routes.
- Mobile sidebar focus trap — requires Sheet/Drawer refactor (currently the drawer is a plain `<aside>` slide-in).
- Charts colour palette tuning for deuteranopia (a11y-21) — Recharts theme-level change.

## [2.4.22] - 2026-04-29

Closes the **last open item from the v2.4.19 reports-module audit** (reports-009 / duplicate generation). With this release every audit finding from the original draconian sweep across the reports module is now resolved.

### Added — In-flight deduplication on `/reports/generate`

A POST `/api/v1/reports/generate` for the same `(organization_id, scan_id, format)` triple while a previous generation is still running now returns the existing `task_id` instead of queuing a duplicate. The response carries `deduplicated: true` so the FE (and telemetry) can tell.

**Why this matters**: pre-v2.4.22 a user clicking "Generate" twice rapidly — or a script opening 100 tabs and clicking each — queued N separate Celery tasks, all running to completion, all writing files to `/tmp/nis2-reports/`, the later one overwriting the earlier in UI state. The v2.4.19 5/min/IP rate limit caps the most egregious abuse, but a curious power user can still create 5 duplicates per minute per IP.

**How it works**:
- New module `app/utils/report_dedup.py` keeps a Redis lock keyed on `(org_id, scan_id, format)` with a 5-minute TTL (matches the FE's poll timeout).
- The route checks the lock before queuing; on a hit, it returns the existing task_id without touching Celery at all.
- A Celery `task_postrun` signal handler in `report_tasks.py` clears the lock when the task finishes — success OR failure — so a legitimate retry / regeneration isn't blocked for the full TTL.

**Failure mode**: every helper in `report_dedup` swallows Redis errors and returns the "no lock present / no-op" answer. If Redis is briefly unreachable, dedup quietly degrades to "no dedup" — the route still works, the user can still generate reports. This is the safest possible failure mode for a polish feature; the alternative (refusing to generate when Redis is down) would be a worse user experience.

**Key isolation** (defence-in-depth):
- Different orgs don't see each other's locks (org_id in the key — even though scan_id alone is globally unique today).
- Different formats stay independent: a PDF render in flight does NOT block a CSV render of the same scan from running concurrently.

### Verified

- 75 unit + **53** e2e (no count change — backend route surface is identical) = **128 green**.
- New `tests/test_report_dedup.py` (**12 tests**) pinning the dedup helper:
  - **Round-trip**: register → lookup returns task_id; clear → lookup returns None.
  - **Key isolation** (3 cases): different org / scan / format don't collide.
  - **TTL pinned to `INFLIGHT_TTL_SEC = 300`** — a regression that drops the EX flag (would make the lock permanent, blocking every future generation for that triple) gets caught.
  - **Failure tolerance** (3 cases): Redis errors → log + safe default (None / no-op). Tested via a `_RaisingRedis` fake that mimics `redis.RedisError` from connection-refused / timeout.
  - **Key shape**: locked to the documented `reports:inflight:` prefix so a rolling deploy doesn't leak orphan keys under a different namespace.
- Manual smoke against running stack:
  - POST #1 mints task `T1` with no `deduplicated` flag.
  - POST #2 (immediately, same scan + format) returns the same `T1` with `deduplicated: true`. ✅
  - POST #3 (same scan, different format `csv`) mints a brand-new task `T3 ≠ T1`. ✅ (format isolation)
  - 5 seconds later, after both tasks complete: `redis-cli --scan reports:inflight:*` returns empty (postrun signal cleared the locks). ✅
  - POST #4 (after the lock was cleared) mints a fresh task `T4 ≠ T1`, no `deduplicated` flag. ✅

### Reports audit closeout — DONE

| Audit ID | Issue | Resolved in |
|---|---|---|
| reports-001 | Cross-tenant report access (RLS bypass) | v2.4.19 |
| reports-002 | Path traversal via scan name | v2.4.19 |
| reports-003 | PDF silent fallback to HTML | v2.4.19 |
| reports-004 | Internal error leakage in /status | v2.4.19 |
| reports-005 | TTL/cleanup of report files | v2.4.20 |
| reports-006 | Hardcoded English in templates | v2.4.21 |
| reports-007 | HTML `lang="en"` hardcoded | v2.4.21 |
| reports-008 | Locale-tagged timestamps | v2.4.21 |
| **reports-009** | **Duplicate generation race** | **v2.4.22 ✅ (LAST)** |
| reports-014 | Markdown injection | v2.4.19 |
| reports-015 | XSS in HTML reports | v2.4.19 |
| reports-016 | CSV formula injection | v2.4.19 |
| reports-017 | XML attribute injection | v2.4.19 |
| reports-018 | No rate limit on /generate | v2.4.19 |

**14 / 14 reports audit findings closed across v2.4.19 → v2.4.22** (4 patches, ~24h of focused work). Reports module is now hardened against cross-tenant access, every form of injection (XSS / CSV / XML / Markdown / path traversal), localised in 5 languages, file-cleaned on a daily janitor, and dedup'd against accidental duplicate generation. Zero regressions on the e2e suite throughout the chain.

## [2.4.21] - 2026-04-29

Closes 3 of the 4 follow-ups postponed from the v2.4.19 reports-module audit: **i18n of report content** (audit reports-006), **HTML `lang` attribute** (audit reports-007), and the locale-tagging side of **timezone localisation** (audit reports-008). All three share the same plumbing — passing the user's locale through the Celery task to the renderer — so they bundle naturally.

### Added — `app/utils/report_i18n.py`

A hand-rolled per-locale label dictionary covering the ~30 strings used in generated reports (PDF/HTML/Markdown/JUnit/CSV). 5 locales × ~30 keys = ~150 hand-written translations.

**Why a dict, not Babel / gettext / i18next**:
- **No new runtime dependency.** Babel pulls 45MB+ of CLDR data when all we need is ~30 label translations per locale. The cost / benefit doesn't pencil out.
- **Self-contained.** The web FE already has `messages/*.json` for its own i18n; mirroring that file format here would couple the worker to the FE bundle (a layering smell). The renderer is a server-side concern with a much smaller string surface.
- **Diff-friendly.** Adding a key is a 5-line PR reviewers can read at a glance.

**Resolution semantics** (`t(locale, key)`):
- Known locale + known key → returns the translation.
- Unknown locale (e.g. `pt`, `zh`, or `None`) → falls back to English. **Wrong language is always better than crashing the worker** for a compliance document.
- Known locale + missing key → falls back to English (defensive — the parity test below would already catch this in CI).
- Completely unknown key (typo in renderer) → returns the key itself, so the report renders with a visible placeholder which gets caught at QA time instead of crashing the worker.

**Locale normalisation** (`normalize_locale`): regional variants (`en-US`, `it-IT`, `pt-BR`) get stripped to their language base; the result is matched against the supported set or falls back to English. Case-insensitive; underscore variant (`it_IT`) accepted alongside the hyphen form.

### Wired through

- **Router** (`routers/reports.py`): `generate_report` reads `current_user.locale` and passes it as the 4th arg to `generate_report_task.delay(...)`.
- **Task** (`tasks/report_tasks.py`): `generate_report_task(scan_id, org_id, format, locale=None)` — backward-compatible signature so any in-flight task queued from a v2.4.20 client (rare, since the queue is empty between releases) still works and falls through to English.
- **Renderers**: every `_gen_*` function (json, csv, markdown, junit, html, pdf) accepts `locale: str = "en"` and uses `_t(locale, key)` for every label. The HTML render also sets `<html lang="{locale}">` — was hardcoded `lang="en"` regardless of content language pre-v2.4.21 (audit reports-007).
- **Result dict**: now carries `locale` (alongside `org_id`) so a curious admin reading the task result can answer "did this user actually request IT, or did the worker default to EN".

### Timestamp policy

Timestamps are intentionally NOT localised:
- **`UTC` is unambiguous across timezones.** A Tokyo team reading the report knows exactly what the timestamp refers to without mental conversion. The audit's reports-008 concern (Tokyo team confused by UTC) is addressed by the explicit `UTC` suffix on every timestamp — pre-v2.4.21 the same suffix was already there; what changes now is the surrounding noun phrase ("**Date:**" → "**Data:**" in IT) gets translated.
- **Compliance auditors correlate report timestamps with logs** from other tools (Splunk, ELK, cloud audit trails) which all standardise on UTC ISO. Forcing those readers to mentally convert "28 aprile alle 14:30" back into ISO is worse than the original problem.
- **User-timezone localisation would require a new `User.timezone` field** — out of scope for this release. Could be added in a future patch.

### Verified

- 75 unit + **53** e2e (no count change — backend route surface is identical) = **128 green**.
- New `tests/test_report_i18n.py` (**12 tests**) pinning the i18n module:
  - **Parity** (3 parametrised tests × 4 non-EN locales = 8 cases): every non-EN locale must have every canonical EN key, no extras (typo defence). A new EN key without all 4 translations fails CI.
  - **`normalize_locale`** (15 parametrised cases): canonical codes pass through, regional variants (`en-US`, `it-IT`, `pt-BR`) get stripped, unknowns fall back to EN, case-insensitive, underscore variants accepted.
  - **`t()`**: known locale + known key returns translation, unknown locale → EN, completely unknown key → key itself, plus a "locales actually differ" guard against an accidental copy-paste that leaves all 5 locales returning the same string.
- Manual smoke against running stack: a user with `locale=it` generates a Markdown report → header reads "Report di Conformità NIS2", "Scansione", "Data", "Punteggio", "Riepilogo Esecutivo", "Critico/Alto/Medio/Basso" all in Italian. HTML report has `<html lang="it">`. Result `task_id` polled via `/status` returns `"locale": "it"` so the rendered locale is observable from outside.

### Postponed to a later release (audit closeout)

- **reports-009 — duplicate-generation UX guard** is the last open item from the reports audit. The current FE `busy` flag plus the v2.4.19 5/min/IP rate limit cover the practical attack surface; this is polish for power users (e.g. a script that opens 100 tabs and clicks Generate). Bundle into a future small patch.
- **`User.timezone`** field for true user-timezone localisation of timestamps (mentioned above).

## [2.4.20] - 2026-04-29

Closes one of the four items postponed from the v2.4.19 reports-module audit: **report file lifecycle / TTL cleanup** (audit reports-005). Without this release, the `/tmp/nis2-reports/` directory shared between the api and worker containers grew unbounded — a deploy with 100s of scans/day would fill the disk in weeks.

### Added — `cleanup_old_reports` Celery beat task

- **New beat schedule entry** `cleanup-old-reports` runs once per day (86400s interval). Sweeps `/tmp/nis2-reports/` for files whose `mtime` is older than `report_ttl_days` (default **30**) and deletes them.
- **Best-effort semantics**: a single `OSError` (file vanished mid-iteration, permission denied on a manually-injected file) is logged and skipped — the next day's run will pick it up. The task always succeeds; the return dict surfaces `removed`, `skipped`, `bytes_freed` to whoever's reading the worker logs.
- **Defensive against a missing reports dir** (someone wiped `/tmp` between runs): logs and exits cleanly with `{removed: 0, skipped: 0, bytes_freed: 0}` rather than crashing.
- **Subdirectory-safe**: only files at the top level of `/tmp/nis2-reports/` are eligible. A subdirectory accidentally created in there (e.g. by manual debugging) is skipped.

### Added — `REPORT_TTL_DAYS` setting

- New `report_ttl_days: int = 30` field in `app.config.Settings`. Set via env var `REPORT_TTL_DAYS` for ops who want a longer / shorter retention. Read at task-execution time (not at process startup), so a config bump propagates without restarting beat.

### Verified

- 75 unit + **53** e2e (no count change — backend route surface is identical) = **128 green**.
- New `tests/test_report_cleanup.py` (8 tests) pinning the cleanup behaviour:
  - `test_removes_files_older_than_ttl` — 3-day-old file with 1-day TTL → removed
  - `test_keeps_files_younger_than_ttl` — 0.5-day-old file with 1-day TTL → kept
  - `test_mixed_directory` — 2 stale + 1 fresh → only the stale removed
  - `test_ignores_directories` — accidentally-created subdir is left alone
  - `test_missing_directory_is_no_op` — wiped /tmp doesn't crash the task
  - `test_empty_directory_is_no_op` — first-deploy state returns 0/0/0
  - `test_default_ttl_is_30_days` — pins the class default; a future code change that drops it accidentally to 0 (which would wipe every report immediately) gets caught here
  - `TestBeatSchedule::test_cleanup_is_in_beat_schedule` — guards against a refactor that drops the schedule entry and silently regresses to the v2.4.18 "/tmp grows forever" state. Pins the schedule key, task path, and 86400s interval.
- Manual smoke against the running stack: `cleanup_old_reports.delay()` runs in 5ms with `removed=0 skipped=0 freed=0 bytes` against an empty directory; cutoff timestamp is correctly 30 days back.

### Postponed to follow-up patches in this audit chain

- **v2.4.21**: i18n of report content (PDF/HTML/Markdown report bodies are still English-only) + locale-aware timestamps. Both share the same plumbing (passing the user's locale through the Celery task) so they bundle naturally.
- **v2.4.22+**: duplicate-generation UX guard. The current `busy` flag in the FE plus the v2.4.19 5/min/IP rate limit on `/generate` cover the practical attack surface; this is more about polishing the experience for power users than a real bug.

## [2.4.19] - 2026-04-29

**Reports module hotfix release.** Closes a chain of blockers in the reports pipeline that surfaced the moment a user actually tried to generate one — five separate causes, all hidden behind each other. Plus a draconian audit pass on the security surface of the report endpoints.

### Fixed — Reports could never generate or download

The user's first scan ("fab") sat at `pending` for ~10 minutes. Investigation surfaced **five sequential bugs**, each of which independently broke the reports flow:

1. **Celery worker had `[tasks]` empty.** `app/tasks/celery_app.py` constructed the Celery app but never imported `scan_tasks` / `report_tasks`, so the `@celery_app.task` decorators never ran. Beat queued `check_scheduled_scans` every minute; the worker logged `Received unregistered task` and discarded the message. Symptom: scans submitted from the UI sat in `pending` forever. **Fix**: explicit imports at the bottom of `celery_app.py` (after the celery_app object is fully constructed, so the task modules can `from app.tasks.celery_app import celery_app` without a circular import).
2. **`Future attached to a different loop` in the worker.** `run_scan_task` calls `asyncio.run(...)`, which mints a fresh event loop per Celery task. The pooled asyncpg connection from the previous task carried a now-closed loop reference; SQLAlchemy threw on the next query. Symptom: the second scan errored, all subsequent scans errored, the worker auto-retried in 30s. **Fix**: new env var `CELERY_WORKER=1` (set in `infra/docker/docker-compose.dev.yml`) routes `app.database` into the same `NullPool` path the integration tests already use.
3. **WeasyPrint native libraries missing.** `from weasyprint import HTML` raised `OSError: cannot load library 'libgobject-2.0-0'` because the slim Python image ships none of the GTK/Pango/Cairo stack. The PDF task caught the `ImportError` and **silently fell back to HTML with a `.pdf` filename** — the user's PDF reader refused the file with no explanation. **Fix**: added `libglib2.0-0`, `libpango-1.0-0`, `libpangoft2-1.0-0`, `libharfbuzz0b`, `libcairo2`, `libffi8`, `fonts-dejavu-core` to the API/worker Dockerfile. The silent fallback also goes — PDF requests now require WeasyPrint and fail with a real error if it can't load.
4. **`/tmp/nis2-reports/` not shared between api and worker containers.** The Celery worker wrote the file to its own `/tmp`; the API's `GET /reports/download/{task_id}` read from the api container's `/tmp` (empty). Every download 404'd. **Fix**: new Docker named volume `reports-data` mounted at `/tmp/nis2-reports` in both services. Persistent across restarts so devs don't lose reports mid-debug; for prod a real shared filesystem or object store is the right answer.
5. **The shared volume came up root-owned.** Docker creates new named volumes as root by default, but the api/worker process runs as the unprivileged `api` user (UID 1001). First write failed `PermissionError: [Errno 13]`. **Fix**: Dockerfile pre-creates `/tmp/nis2-reports` with `chown api:api` *before* `USER api`, so the named volume on first mount inherits the directory's ownership.

End-to-end test after the fix chain: 5 of 6 report formats (PDF / HTML / JSON / CSV / Markdown) generate and download in under 3 seconds; the 6th (JUnit) hit the new 5/min rate limit on the second test run, confirming the limit works.

### Fixed — `MISSING_MESSAGE` runtime error in audit-log page

`packages/web/src/app/dashboard/settings/audit-log/page.tsx:123` called `tc("page")` against the `common` namespace, which has no `page` key. next-intl threw `MISSING_MESSAGE` and the page broke at runtime in IT/FR/DE/ES (and any locale where the parent's `||` fallback chain doesn't trigger because next-intl raises rather than returning falsy). **Fix**: route through the `scans` namespace's existing `t("page", { n: page })` — same widget rides on /scans, /reports, audit-log, and the rest, so re-using the keys keeps translations in one place.

### Reports module security audit (v2.4.14-style draconian sweep)

The audit found five **🔴 BLOCKERS**, all addressed in this release:

- **reports-001 / Cross-tenant report access.** The `/status/{task_id}` and `/download/{task_id}` endpoints accepted any authenticated user — a user from org A could enumerate task UUIDs and fetch org B's reports. **Fix**: `generate_report_task` stamps `org_id` into its result dict; both endpoints verify the caller's `membership.organization_id` matches before returning anything. Cross-tenant attempts get **404** (same shape as a not-found task) so an attacker can't tell if a UUID maps to a real-but-other-org task or a non-existent one.
- **reports-002 / Path traversal via `scan.name`.** A scan named `../../../../etc/passwd` would resolve `os.path.join` outside `/tmp/nis2-reports/` — the writer could clobber arbitrary files reachable by the worker process. **Fix**: new `_safe_basename(name)` whitelists alphanumerics / `-` / `_`, replaces everything else with `_`, caps at 64 chars, falls back to `report` on empty input.
- **reports-014 / Markdown injection in user content.** Finding messages, remediation notes, and executive summaries with `|`, `*`, `_`, `[`, `]`, `<`, `>`, `` ` `` broke the table layout or injected raw HTML in lenient Markdown viewers. **Fix**: new `_md(value)` helper backslash-escapes structural characters and collapses newlines.
- **reports-015 / XSS in HTML reports.** `scan.name`, `scan.executive_summary`, every finding's `message` / `category` / `target` / `remediation`, and every asset's `target` / `ip` were string-concatenated into the HTML template raw. A scan named `</title><script>alert(1)</script>` executed JS in any browser that opened the report (or in WeasyPrint's print pipeline for the PDF version). **Fix**: every interpolation now goes through `html.escape()` via the `_h()` shorthand.
- **reports-016 / CSV formula injection.** Cells beginning with `=`, `+`, `-`, `@`, tab, or `\r` are auto-evaluated by Excel, LibreOffice, and Google Sheets when the file is opened. A finding message of `=cmd|'/c calc'!A1` would launch `calc.exe` on a Windows recipient's machine. **Fix**: `_csv_safe(value)` prefixes risky cells with a single quote (which spreadsheet apps strip on display).
- **reports-017 / XML attribute injection in JUnit format.** Finding messages with `"` or `&` could break the XML attribute structure or inject sibling attributes. **Fix**: `_xml_attr(value)` uses `xml.sax.saxutils.escape()` plus an explicit `"` → `&quot;` mapping; body text uses `_xml_text(value)`.

### Reports module — additional hardening

- **Rate limit on `/generate`** (audit reports-018): `5/min/IP`, sharing the same slowapi instance as the rest of the auth/org endpoints. Report generation can take 30+s of CPU on a worker for a 50k-finding scan; without a limit a single client could pin every Celery worker.
- **Sanitised error messages** (audit reports-004): the previous version returned `str(result.result)` on `FAILURE`, leaking internal exception text (e.g. `Permission denied: /tmp/nis2-reports`) to the client. Now the worker error is logged server-side and the client sees a generic `Report generation failed` string.
- **PDF silent fallback removed** (audit reports-003 / reports-010): `_gen_pdf` no longer catches `ImportError` and degrades to HTML with a `.pdf` extension. WeasyPrint is required; if the import fails, the task fails and the user sees the error.

### Verified

- **53/53 e2e green** (no test count change — backend test surface is the same).
- 5/6 report formats round-tripped end-to-end (PDF generates a real `%PDF-1.7` 33KB file; the 6th hit the new rate limit on the second run, confirming it works).
- `ruff check` matches CI's exact invocation, all clean.
- All 5 i18n locales validate; **668 leaf keys** unchanged from v2.4.18.

### Postponed to a later release

- **Report file TTL/cleanup** (audit reports-005). A Celery beat job that sweeps `/tmp/nis2-reports/` once a day is the right move; not in scope for this hotfix.
- **i18n of report content** (audit reports-006/008). PDF/HTML/Markdown report bodies are still English-only. Needs a Jinja2 template per locale + a way to pass the user's locale through the Celery task. Larger refactor.
- **Duplicate-generation UX warning** (audit reports-009). Currently two clicks fire two tasks; second overwrites first in UI state. Nit.

## [2.4.18] - 2026-04-29

Closes the **last open audit item** from the v2.4.14 draconian UX review: a user can now self-serve a new organization from the org-switcher dropdown without needing an admin elsewhere to invite them. With this release the entire B-DRA / S-DRA / N-DRA / O-DRA backlog is closed.

### Added — `POST /api/v1/organizations`

- **Body**: `{"name": "<string>"}` (1..256 chars). The slug is derived server-side from the name via `slugify()` (extracted to `app/utils/slug.py` so both `auth.register` and `organizations.create` share the implementation). On collision the route appends `-1`, `-2`, … until the slug is free; if the name slugifies to an empty string (unicode-only / emoji name) it falls back to `org-<8-hex>` so the UNIQUE index can't be hit with a blank slug.
- **Authorization**: any authenticated user. The caller is automatically added as the new org's admin with `accepted_at = now()` — no invite/accept loop for self-created orgs.
- **Audit log entry** `organization.created` written under the *new* org_id (so it shows up in that tenant's trail — where a curious admin will look first when wondering "when was this org born"). `details` records `name`, `slug`, and `self_created: true`.
- **Rate limit** `5/min/IP`. Genuine org creation is a rare action (users typically own 1-3 orgs in their lifetime); the limit makes a runaway script obvious in the access logs.
- **CSRF** required (state-changing, has session cookie).
- Returns `OrgResponse` (same shape as `GET /{org_id}`) with HTTP 201. The FE caller is expected to follow up with `POST /auth/switch-org` to move into the new tenant; this route deliberately does **not** remint the JWT itself so a power user can stay in their current org context if they want.

### Added — `<OrgSwitcher>` enhancement

- New "Create new organization" entry in the dropdown footer (with a `Plus` icon, primary-coloured to read as an action). Opens a `<Dialog>` with a single name input.
- **Visibility rule changed**: the switcher now renders for **single-org users too** — previously it was hidden when `orgs.length <= 1` since there was nothing to act on; now there's always the create-new entry point. (Empty/loading states still render `null`.)
- On successful create:
  1. The mutation invalidates the `["orgs"]` query so the dropdown's list refreshes,
  2. **Auto-switches into the freshly-created org** — same UX as Vercel/Linear/etc. The user just spun up a tenant; they almost certainly want to land in it.
  3. If the auto-switch itself fails (rate limit, network blip), the org-create still counts as a success — the user can switch manually from the dropdown.
- `useCreateOrg()` hook in `hooks/use-orgs.ts`.
- `api.createOrg({ name })` in `lib/api-client.ts`.

### Refactored

- `_slugify` extracted from `routers/auth.py` to `app/utils/slug.py` (now exported as `slugify`). Both call sites (`auth.register` and `organizations.create`) import from the same module so a future tweak to the slug rules propagates everywhere.

### Verified

- 75 unit + **53** e2e (was 50 in v2.4.17) = **128 green**.
- New `TestCreateOrg` (3 tests):
  - `test_create_with_empty_name_422` — Pydantic min_length=1
  - `test_create_unauthenticated_401` — no cookie / Bearer
  - `test_full_flow_register_create_switch` — register a temp user → from their session create a 2nd org → list orgs (must be 2, both with the user as admin) → switch into the new org → verify the JWT carries the new org_id → switch back. Pays **zero `/login`** by reusing /register's set-cookie throughout.
- All 5 i18n locales validate clean and re-pass parity at **668 leaf keys** (was 658 in v2.4.17). +10 new keys × 5 locales = **50 new translations** under `orgSwitcher.create*`.
- `ruff check` matches CI's exact invocation, all clean.
- TypeScript: 16 pre-existing recharts errors in `dashboard/page.tsx` and `reports/page.tsx` unchanged (Next.js production build tolerates them).

### Audit closeout

This release closes the **last B-DRA / S-DRA / N-DRA / O-DRA item** from the v2.4.14 draconian UX audit. Across **5 patch releases** (v2.4.14 → v2.4.18) all 22 audit findings have been triaged: 19 fixed, 2 confirmed false flags, 1 deemed not worth fixing (color of empty-state icon — a tradeoff). See the v2.4.17 release notes for the full closeout matrix.

### Postponed

- A public **delete-organization** route — currently the only way to remove an org is via direct DB. Not urgent for self-hosted; add when SaaS / multi-tenant requirements demand it.
- Per-org branding (logo, primary colour) configurable from the org settings page — nice-to-have for the consultant-managing-multiple-clients persona; not in scope for a self-serve-create patch.

## [2.4.17] - 2026-04-29

Closes the entire **S-DRA-* / O-DRA-*** polish backlog from the v2.4.14 audit. All 5 SERIOUS items + 4 of 5 OPPORTUNITIES (the 5th, "create new organization self-serve", remains scoped for a future release that adds the BE endpoint). Pure FE patch — no backend changes.

### Fixed (audit S-DRA-*)

- **S-DRA-01 / Date format ignored the app locale.** Every page rendering a date called `format(new Date(...), "MMM d, yyyy")` from `date-fns` directly, which falls back to en-US regardless of the next-intl locale. New `useFormatDate` hook in `lib/dates.ts` bridges `next-intl`'s `useLocale()` to date-fns' `Locale` objects (en/it/fr/de/es bundled — only the 5 the UI ships, so no 60+ unused locale chunks bloat the bundle). Applied to **7 pages**: dashboard, scans list, scan detail, scan schedules, audit log, api-keys list, reports, team. Italian users now see "28 apr 2026" instead of "Apr 28, 2026".
- **S-DRA-02 / Findings filter not debounced.** Each click on the severity / status / category Select dropdowns fired `useFindings(params)` immediately — three quick clicks = three concurrent `/api/v1/findings` requests with no arrival-order guarantee. The table could end up showing the second click's results rather than the third. New `useDebounce` hook (250ms — UX sweet spot, faster feels twitchy on dropdowns, slower feels laggy). Applied to all three filters.
- **S-DRA-03 / Cron expression had no client-side validation.** `cron_expression` schema only required `min(5)` chars, so "abcde" passed and the API returned a generic 422. Added a regex enforcing the 5-field shape (minute / hour / day / month / weekday) — accepts numbers, lists `1,2,3`, ranges `1-5`, wildcards `*`, and steps `*/2`. Server-side `croniter` still owns the field-level semantics (range bounds, step validity); this regex is a fast-fail to give the user a clear error before round-trip. Error messages are i18n keys (matching the project pattern) and a permanent help line under the input explains the format.
- **S-DRA-04 / Reports pagination was hardcoded English.** "Previous" / "Page N" / "Next" rendered as literal strings. Re-uses the `scans` namespace's existing pagination keys (same widget on both pages — no need to mint duplicates).
- **S-DRA-05 / Severity badge value rendered raw.** The findings page rendered `{finding.severity}` directly ("critical", "high", "medium" lowercase letterali) next to a translated table header — visually mismatched. Now goes through `t(severity.toLowerCase())` resolved against the `findings` namespace. Same fix applied to status badges (was rendering `finding.status.replace("_", " ")` → "false positive" lowercase) — now mapped through proper i18n keys (camelCase `inProgress`, `falsePositive`).

### Added (audit O-DRA-*)

- **O-DRA-01 / `Cmd+K` command palette.** New `<CommandPalette>` component built on `cmdk` (already in dependencies). Mounted in the dashboard layout so the keyboard shortcut listener attaches once and the dialog is reachable from every authenticated screen. v1 lists every primary navigation entry plus action commands ("New scan", "Manage schedules") with their lucide icons; cmdk gives us fuzzy-search filtering and the standard ⌘K UX. Each command is searchable by **both** its localised label AND its canonical key, so an Italian user typing "scansioni" and an English user typing "scans" hit the same row. Cross-resource search (scan names, finding targets) is intentionally postponed — it needs a backend search endpoint we don't have yet.
- **O-DRA-03 / Cron presets** — already shipped previously as `presets.dailyAt9` / `weeklyMonday` / etc. in the schedules form; the v2.4.14 audit was a false flag. Confirmed working with the new validation in place.
- **O-DRA-04 / Bulk export findings as CSV.** New "Export CSV" button in the bulk actions bar (visible alongside "Apply" and "Clear" once at least one row is selected). Generated client-side from already-loaded TanStack Query data — no new backend endpoint needed. RFC 4180 quote-escaping; UTF-8 BOM prefix so Excel imports accented characters cleanly. Filename pattern `nis2-findings-<yyyy-MM-dd>.csv` matches the reports module convention.
- **O-DRA-05 / Sidebar badge with critical findings count.** Destructive-pill badge next to the "Findings" nav item showing the count of severity-critical findings in the active org. Pulled from the existing `useFindingStats()` hook (no new endpoint). On the collapsed sidebar (icon only) the badge degrades to a tiny dot so it doesn't fight the icon for space; on the expanded sidebar it shows the count (with `99+` overflow). `aria-label` includes the count for screen-reader users.

### Polished

- **N-DRA-03 / Status label casing on findings table.** Was `finding.status.replace("_", " ")` → "false positive" lowercase. Now mapped through localised camelCase keys.
- **`<a href="mailto:">` consultation CTA**, server-side `<Link>` rendering, etc. — no changes; their audit notes were future-iteration nudges.

### i18n totals

- **+17 leaf keys × 5 locales = 85 new translations.**
- All 5 locale files validate as JSON and re-pass parity check at **658 leaf keys** (was 641 in v2.4.16).
- New keys land in `nav.criticalBadgeAria`, `findings.exportCsv` / `exportedCount`, `schedulesPage.{nameRequired,cronRequired,cronInvalid,cronHelp}`, and the brand-new `commandPalette` namespace (10 keys).

### Verified

- 75 unit + **50** e2e (no test count change — backend untouched) = **125 green**.
- `ruff check` matches CI's exact invocation, all clean.
- TypeScript: 16 pre-existing recharts errors in `dashboard/page.tsx` and `reports/page.tsx` unchanged (Next.js production build tolerates them; CI Web Build still passes).
- All touched FE pages return 200 against the running dev stack; no `MISSING_MESSAGE` warnings in the dev container logs.

### Postponed

- **"Create new organization" self-serve** — currently only path to a 2nd membership is via invite. A `POST /api/v1/organizations` route owned by `current_user` is reasonable but out of scope for a polish patch. Scoped for v2.4.18.
- **Command palette v2** — cross-resource search (scans by name, findings by target, assets by hostname). Needs a backend search endpoint. Scoped for a future release.

## [2.4.16] - 2026-04-29

Closes the last blocker from the v2.4.14 draconian UX audit (B-DRA-02): a user with memberships in multiple organizations can now switch between client tenants without logging out. README has marketed multi-tenancy "for NIS2 consultants managing multiple clients" since v1.0; until this release there was no UI to act on it. Backend already had RLS policies on every tenant-scoped table and the JWT carried `org_id` (since B10 in v2.4.12) — the missing pieces were the **switch endpoint** and the **switcher UI**.

### Added — `POST /api/v1/auth/switch-org` (audit B-DRA-02)

- **Body**: `{"organization_id": "<uuid>"}`. Pydantic enforces UUID format; malformed payload returns 422 before any DB work runs.
- **Authorization**: requires the existing cookie or Bearer session. Looks up `(current_user.id, payload.organization_id)` against the eager-loaded `Membership` rows; if no match, returns **403** ("you are not a member of the target organization") rather than 404 — the org may exist; the membership doesn't.
- **Token rotation**: reuses `_build_token_response` (the same helper as `/login`, `/register`, `/refresh`, `/change-password`), minting fresh access / refresh / csrf tokens with the new `org_id` claim and the role from the target membership. Cookies are rotated via `Set-Cookie` so the FE picks up the new tenant transparently.
- **Audit log entry** `user.org_switched`, written under the *target* org so the security team finds it where they look ("who accessed our tenant today"). `details` records `from_org_id` (the previous JWT claim — `null` for legacy tokens predating v2.4.12) and `to_role`.
- **Rate limit**: `10/min/IP`. UI action, not a credential surface; the limit makes brute-force enumeration of org IDs uninteresting (combined with the RLS guard, which already flatly refuses cross-org reads).
- **CSRF**: required (state-changing, has session cookie — middleware enforces double-submit).

### Added — Frontend `<OrgSwitcher>` component

- New file `components/layout/org-switcher.tsx` plus `hooks/use-orgs.ts` (`useOrgs` + `useSwitchOrg` mutation).
- **Renders only when the user has 2+ memberships** — single-org users (the vast majority of self-hosted installs) see no extra chrome.
- Lives at the top of the sidebar, immediately under the logo, with both expanded (full button showing "Active organization" / `<orgName>`) and collapsed (icon-only) layouts.
- On switch:
  1. POSTs to `/auth/switch-org` (cookies rotate via `Set-Cookie`),
  2. updates the auth-store's `orgId` so RLS-keyed queries (`["scans", orgId]`, `["members", orgId]`, etc.) re-key correctly,
  3. **clears the entire TanStack Query cache** — every screen's data is RLS-scoped on the server, so stale results from the previous tenant must not leak into the new view (a per-key invalidate would race with components reading the stale data on the same render),
  4. `router.refresh()` to re-run the App Router's hydration against the new tenant.
- Accessible: `aria-label` on the collapsed icon trigger names the active org and the action ("Active organization: Acme. Click to switch.").
- New `orgSwitcher` namespace in `messages/*.json` — **5 leaf keys × 5 locales = 25 new translations**.

### API client

- `api.switchOrg(organizationId)` returns the new `TokenResponse`. Caller is expected to clear the query cache after success — the `useSwitchOrg` mutation does this automatically.

### Verified

- 75 unit + **50** e2e (was 46 in v2.4.15) = **125 green**.
- New `TestOrgSwitch` (4 tests):
  - `test_switch_with_invalid_uuid_422` — malformed UUID body
  - `test_switch_to_unknown_org_403` — well-formed UUID with no membership
  - `test_switch_unauthenticated_401` — no cookie / Bearer
  - `test_full_round_trip_multi_org` — register a temp user → temp invites the canonical test user (gives them a 2nd membership) → switch to the new org → switch back → cleanup the temp membership. Pays **zero extra `/login`** by reusing the module-scoped `client` fixture; `try/finally` always restores the original org so the module client's cookies are not poisoned for downstream tests.
- All 5 i18n locales validate clean and re-pass parity at **641 leaf keys** (was 636).
- Local `ruff check` matches CI's exact invocation, all clean.

### Postponed to a later release

- **B-DRA-02 part 2 / "Create new organization" surface** — currently a user only joins additional orgs via being invited to an existing one. A `POST /api/v1/organizations` route that creates a new org owned by `current_user` (giving the SaaS user a self-serve way to spin up a second tenant) is reasonable but out of scope for this patch.
- **S-DRA-* / O-DRA-*** — date locale via next-intl, findings filter debouncing, cron preset chips, sticky table headers, locale-aware severity badges, real `cmdk` command palette, bulk export findings, drag-drop asset import. Bundled into v2.4.17+.

## [2.4.15] - 2026-04-29

This release closes the i18n / dead-code / destructive-action backlog flagged by the v2.4.14 draconian UX audit. No backend changes — purely frontend cleanup. The recurring theme: pages that *had* an i18n namespace defined but never imported `useTranslations`, plus a few fake-UX leftovers from earlier prototypes.

### Fixed (audit B-DRA-* — UI/UX backlog)

- **B-DRA-01 / Fake search bar killed.** `components/layout/header.tsx` rendered a `<Button>` styled as a search input with a `Ctrl+K` kbd hint and no `onClick` — a Potemkin search the user could click forever. Removed. The `header.searchPlaceholder` i18n key is left in the bundle so a real `cmdk` command palette (planned for v2.4.16+) can wire up without a translation round.
- **B-DRA-03 / Dashboard landing page wasn't translated.** `app/dashboard/page.tsx` — the most-visited page after login — never imported `useTranslations`. Every KPI label, chart title, empty state, table header was hardcoded English even though the `dashboard` namespace in `messages/*.json` already had keys for nearly all of it. Wired up; severity labels in the chart now route through the `findings` namespace so the BarChart axis localises with the rest of the UI; status badges in "Recent Scans" use the `scans` namespace.
- **B-DRA-04 / `/dashboard/scans/new` form was 100% hardcoded English.** Form titles, Card sections, feature row labels (`["dns_checks", "DNS", "DNS record analysis"]`), advanced settings, and three `toast.error / toast.success` calls — all literal strings on the most critical user flow (launching a scan). New `scansNewPage` namespace (40 keys × 5 locales = 200 translations).
- **B-DRA-05 / `/dashboard/scans/[id]/compare` was 100% hardcoded English.** Page titled "Scan Comparison", "Select Scan to Compare Against", "New Findings", "Resolved", "Persistent" — none of it through `t()`. New `scansComparePage` namespace (19 keys × 5 locales = 95 translations); table headers reuse the `findings` namespace.
- **B-DRA-06 / `/dashboard/scans/[id]` had hardcoded ITALIAN.** Worse than hardcoded English — the page mixed "Scansione non trovata", "Riepilogo Esecutivo", "Matrice Conformità NIS2 Art. 21", "Host analizzati", tab labels in Italian into an otherwise-English UI. Leftover from the original Italian prototype that survived the i18n round 1 sweep. New `scanDetailsPage` namespace (29 keys × 5 locales = 145 translations); compliance status labels reuse `compliancePage`; severity labels reuse `findings`.
- **B-DRA-07 / Dead `sampleFindings` array shipped fake employee emails.** `app/dashboard/findings/page.tsx` had a 12-row hardcoded array (`john@example.com`, `jane@example.com` as `assigned_to` values) declared at module scope and **never referenced** — pure dead code dating from before v2.4.5's mock kill. The route already uses `useFindings` against the real API. Deleted.
- **B-DRA-08 / Member removal had no confirmation dialog.** `app/dashboard/settings/team/page.tsx` — clicking "Remove Member" in the row dropdown fired `handleRemove()` immediately. A misclick removed a colleague; the only feedback was a success toast after the fact. Now routes through a single `<Dialog>` driven by a `confirmAction` state. Confirms on **two destructive actions**: any removal, and any role change that demotes an admin (`admin → auditor / viewer`). Promotions and lateral non-admin moves stay one-click — friction would outweigh the regret cost. 5 new keys in `teamPage` namespace (`confirmRemoveTitle`, `confirmRemoveDescription`, `confirmDemoteTitle`, `confirmDemoteDescription`, `confirmDemoteAction`) × 5 locales = 25 translations.
- **B-DRA-09 / Organization settings zod error was a literal English string.** `app/dashboard/settings/organization/page.tsx:22` had `z.string().min(1, "Organization name is required")` instead of an i18n key. Aligned with the login / register / profile pattern — error message is a key resolved via `t(error.message)` at render. Added `organizationPage.nameRequired`.

### Polished (audit N-DRA-*)

- **N-DRA-01 / Avatar fallback initial.** `components/layout/header.tsx` fell back to a hardcoded "U" when `user.full_name` was empty. Now prefers the first letter of the email (always present for an authed user); only falls back to "U" when both are absent — which only happens during the brief window before `/auth/me` hydrates.

### i18n totals

- **+99 leaf keys × 5 locales = 495 new translations.**
- All 5 locale files validate as JSON and re-pass parity check at **636 leaf keys** (was 537 in v2.4.14).
- **Zero MISSING_MESSAGE warnings** in the dev container logs after dashboard / scans-new / scans-detail / scans-compare / team / organization page renders.

### Verified

- 75 unit + **46** e2e (no test count change — backend untouched) = **121 green**.
- TypeScript: 16 pre-existing recharts errors in `dashboard/page.tsx` and `reports/page.tsx` unchanged (Next.js production build tolerates them; CI Web Build still passes).
- All four touched FE pages (`/dashboard`, `/dashboard/scans/new`, `/dashboard/settings/team`, `/dashboard/settings/organization`) return 200 against the running dev stack.
- IT locale spot-check: dashboard renders "Scansioni Totali", "Punteggio Medio", "Risultati Totali", "Asset Monitorati", "Hai bisogno di supporto esperto…", "Richiedi consulenza" — fully localised.

### Known limitations / postponed

- **B-DRA-02 (multi-tenant org switcher)** — `api.listOrgs()` exists but no UI consumes it. Scoped to v2.4.16 because it needs a backend `POST /auth/switch-org` endpoint that remints the JWT with the new `org_id`, plus a dropdown in the user menu. Larger than fits this patch.
- **S-DRA-01..05 + remaining N-DRA / O-DRA** (date-locale via next-intl, findings-filter debouncing, cron preset chips, sticky table headers, locale-aware severity badges, real `cmdk` command palette) — bundled into v2.4.16+ polish + features.

## [2.4.14] - 2026-04-28

### Fixed (CI)

- **`ruff` lint failure on `main`**: `app/routers/audit.py` carried an unused `from sqlalchemy.orm import selectinload` left over from an earlier refactor. The `Lint API` job in CI exited 1; the rest of the pipeline (api/integration/scanner/policy/trivy/gitleaks/pip-audit) was already green. Removed the import.

### Added (audit blocker B05) — Forgot-password / Reset-password

The "I forgot my password" flow finally exists. Before this release a user who couldn't log in had no recovery path: there was a `forgotPassword` i18n key on the login screen but no link, no route, and no backend. Now:

- **`POST /api/v1/auth/forgot-password`** (`5/min/IP` slowapi limit). Always returns 204, regardless of whether the email is on file. The same response on every input is the only structural protection against using this endpoint as a registered-email enumeration oracle.
- **`POST /api/v1/auth/reset-password`** (`10/min/IP`). Verifies a single-use token, sets the new password (passlib bcrypt, 8-char minimum mirroring `RegisterRequest` and `ChangePasswordRequest`), bumps `password_changed_at = floor(now) + 1s` so every other still-active session for this user gets bounced on its next request (same JWT iat watermark mechanism as v2.4.13's change-password).
- **Single-use semantics.** Tokens are stored as `sha256(raw_token).hexdigest()` — the DB never sees the raw value. `used_at` is stamped on first acceptance; subsequent attempts collapse into a single 400 with the same generic message as unknown / expired so attackers can't tell which class their token fell into.
- **30-minute TTL** (`RESET_TOKEN_TTL_MINUTES=30` default). Configurable via env.
- **`PasswordResetToken` model**: `user_id` (FK CASCADE), `token_hash` (sha256, unique, indexed), `expires_at`, `used_at`. Not tenant-scoped — the forgot flow runs without org context.
- **Email plumbing via stdlib `smtplib`** (`packages/api/app/utils/email.py`). No new runtime dependency. Sends are offloaded to `asyncio.to_thread` so the event loop never blocks. When `SMTP_HOST` is unset AND `ENVIRONMENT != "production"`, the message is captured into a process-local `_DEV_OUTBOX` (max 100) instead — read back by the e2e suite via the dev-only `GET /api/v1/auth/debug/last-email`. Production with no SMTP raises rather than silently dropping.
- **CSRF**: forgot/reset are added to `EXEMPT_PATHS` (no session yet at that point — there's no cookie to double-submit).
- **Audit log entry** `user.password_reset` so an admin can see "password reset by token at T from IP".

### Added — Frontend pages

- **`/forgot-password`** — entry point. Single email input, success state mirrors the API contract: identical UI on submitted whether the email was known or not. Toast / banner do **not** branch on whether the API call succeeded; the only signal a legitimate user gets is the email landing in their inbox.
- **`/reset-password?token=…`** — completion. Pre-flight 400 if the token is missing from the URL ("link is broken" path), single error bucket for "invalid / expired / used" matching the server's response discipline. Successful reset shows a green confirmation card and bounces to `/login` after 1.5s.
- **Login page** now has a "Forgot Password?" link next to the password field (was an i18n key with no rendered consumer).
- **`api.forgotPassword(email)` / `api.resetPassword(token, newPassword)`** in `lib/api-client.ts`.
- **i18n**: 21 new leaf keys × 5 locales = **105 new translations** under `forgotPasswordPage` and `resetPasswordPage` namespaces.

### Wired (audit blocker B11 follow-up) — API-key auth on read endpoints

The `get_api_key_org` dependency from v2.4.12 was sound but had no consumers — keys could be issued and revoked, but never authenticated anything. v2.4.14 wires it in:

- **`get_org_id_dual_auth`** (new dependency): resolves the active organization_id from either a JWT cookie session OR a `nis2_*` Bearer token. Falls through to `get_current_user → get_current_org` for the JWT path; calls `get_api_key_org` for the API-key path. Routes that just need an org_id for RLS scoping (read endpoints) can swap one dep for the other without touching their bodies.
- **Read endpoints converted**: `GET /api/v1/scans`, `GET /api/v1/scans/{id}`, `/results`, `/findings`, `/compare/{other}` (5 in scans), `GET /api/v1/findings`, `/stats`, `/{id}` (3 in findings), `GET /api/v1/assets`, `/{id}` (2 in assets) — **10 endpoints** total.
- **Mutation endpoints (POST / PATCH / DELETE) intentionally stay JWT-only.** They write into the audit log + `created_by` columns; an API key has no user identity to attribute the change to without a deeper schema change. Pipelines that need to *create* scans still use a service-account login. We can revisit this if the demand surfaces.
- **Cookie + API-key collision guard**: if both an `access_token` cookie AND a `nis2_*` Bearer token are present, the JWT path wins. This prevents a stale API key on the browser tab from accidentally downgrading the auth path.

### Verified

- 75 unit + **46** e2e (was 36 — added 6-test `TestApiKeyAuth` covering list-scans/findings/assets via API key, invalid-key 401, revoked-key 401, last_used_at stamping; plus 5-test `TestForgotPassword` + `TestResetPassword` covering silent-on-unknown-email, valid-token resets, single-use, invalid-token rejected) = **121 green**.
- `TestApiKeyAuth` is positioned **before** the password-rotation block in `test_e2e_live.py` because the rotation tests stamp `password_changed_at` and invalidate the module-scoped `client` fixture's cookies — running API-key tests after them would 401 every cookie-auth setup call.
- Local lint clean: `ruff check packages/scanner/nis2scan/ --select=E,W,F --ignore=E501` + same for `packages/api/app/` both pass with "All checks passed!".

### Translations

+21 leaf keys × 5 locales = **105 new translations**. All locale files validate clean.

### Postponed to a later release (per user direction)

- **B06 + B07** proper invite tokens + email + accept-after-register flow. The current `inviteMember` endpoint silently auto-binds the invitee to the org without their consent. The fix is non-trivial (new model, accept-token route, email template, edge cases for invitees who already have an account) and was deferred so v2.4.14 could ship the more user-visible B05 + API-key wiring first.

## [2.4.13] - 2026-04-28

### Fixed (audit blocker B04)

- **Password change UI was a lie.** The Profile page sent `current_password` + `new_password` to `PATCH /auth/me`. That route validated against `UserUpdate` — a Pydantic schema declaring only `full_name`, `locale`, `avatar_url`. Pydantic silently dropped the unknown fields, the route returned 200, the toast said "passwordUpdated", and the password hash never changed. Users believed they had rotated a compromised password and remained compromised. Fixed by introducing a real endpoint.

### Added — `POST /api/v1/auth/change-password`

- **Pydantic body** (`ChangePasswordRequest`): `current_password` (required, 1..128) + `new_password` (required, 8..128). The `min_length=8` is what enforces the password floor — Zod on the FE mirrors it.
- **passlib `verify`** of the current password against `password_hash` → 401 on mismatch (constant-time comparison; no enumeration leak).
- **No-op refusal**: setting the new password equal to the current one returns 400 instead of pretending success. The verify-against-old-hash check uses passlib too, so it costs one bcrypt round but avoids the silent-success footgun.
- **bcrypt rehash + persist** the new password.
- **`password_changed_at` watermark**. New `User.password_changed_at` column (nullable; legacy users read as "never rotated"). Stamped to `floor(now) + 1s` on every change. The JWT decode path in `dependencies.py` and `/auth/refresh` now compares `iat` against this watermark **in epoch seconds**, rejecting any token whose `iat` is strictly less. Result: every other session for this user gets bounced to `/login` on its very next request, with no per-jti tracking required.
- **`iat_override` plumbed through `_build_token_response` → `create_access_token` / `create_refresh_token`**. The change-password handler mints the new tokens with `iat = next_second`, the same value as the watermark, so the active tab keeps working (its iat is == watermark, comparison is `<` not `<=`) while every other tab loses its session.
- **Audit log entry** (`user.password_changed`, `resource_type=user`, `details={self_initiated: True}`) so the compliance team can answer "when did Alice last rotate her password" without grepping postgres logs.
- **slowapi rate limit** `5/minute` on the endpoint to slow credential-stuffing attempts that try old passwords as the "current".
- **CSRF**: not in the exempt list (login/register/refresh/logout); state-changing authenticated mutation, double-submit token required.

### Subtle bug found & documented during e2e bring-up

JWT encodes `iat` as epoch seconds (truncated). `datetime.now(utc)` carries microseconds. Comparing `datetime(iat) < datetime(password_changed_at)` was unstable in the same wall-clock second: a token minted at `02.500s` had `iat = 02.000s`, which compared as `< 02.345s` (the watermark stored with microseconds). Solution: store the watermark as `floor(now) + 1s`, mint new tokens with `iat = next_second`, **compare in epoch seconds on both sides**. Documented in `dependencies.py` and `/refresh` so a future maintainer doesn't undo it.

### Frontend

- `api.changePassword({current_password, new_password})` (real endpoint, not `updateMe`).
- Profile page: schema rejects `new === current` client-side too (better UX than the 400 round-trip), zod messages live as i18n keys (`profilePage.currentPasswordRequired`, `auth.passwordMin8`, …) resolved via `t()` at render. Error toasts pattern-match the server detail to surface localised hints.
- Inputs got proper `autocomplete` attributes (`current-password`, `new-password`) so password managers behave.
- Post-success toast description: "Other devices and tabs will need to sign in again" — sets the right expectation.

### Translations

+9 leaf strings × 5 locales = **45 new translations**. All locale files validate at **516 leaf strings**.

### Verified

- 42 unit + **36** e2e (was 32 — added a 4-test `TestChangePassword` block: wrong-current 401, weak-new 422, same-as-current 400, success-with-cross-session-invalidation 204+200/401) = **78 green**.
- The `TestChangePassword` block is positioned at the **bottom of `test_e2e_live.py`** because the password change watermark invalidates every JWT issued before it — including the module-level `client` fixture's own access cookie. Running it earlier would cascade 401s into every subsequent test.

### Still pending (audit follow-up — v2.4.14)

- **B05** forgot-password / reset-password (token-based; needs SMTP plumbing or a copy-paste-token compromise).
- **B06+B07** proper invite tokens + email + accept-after-register (today the invite endpoint silently auto-binds the user to an org without consent).
- Wire `get_api_key_org` into `scans` / `findings` / `assets` so API keys actually authenticate API calls (the dependency is sound, just unused).
- 9 serious + 5 nits from the audit.

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

### Fixed (Davide — round 3)
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

### Fixed (reported by Davide — round 2)
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

Reported by Davide. Thanks Davide.

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
