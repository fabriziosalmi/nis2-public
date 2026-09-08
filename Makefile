# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public

.PHONY: dev dev-up dev-up-fresh dev-down dev-logs api-logs web-logs db-migrate db-upgrade db-seed db-provision-app-role version version-check version-check-release version-set test test-api test-scanner lint check test-integration test-e2e test-web h5-validate verify clean clean-all prod prod-preflight prod-up prod-down

# ─── Cross-platform Python detection ─────────────────────────────────
# v2.4.28: pre-2.4.28 the Makefile invoked `python` literally, which on
# a Windows host without a real Python install gets captured by the
# Microsoft Store stub at %LOCALAPPDATA%\Microsoft\WindowsApps\python.exe.
# That stub exits 9009 with a localised "Python non trovato — eseguire
# senza argomenti per installare dal Microsoft Store" message and the
# whole `make clean-all` fails before scripts/clean.py even runs.
# Reported by Davide
#
# Detection priority:
#   - python3:  Linux / macOS / WSL canonical name
#   - py:       Windows Python launcher shipped with python.org installer
#               (NOT the Store stub — `py` only exists when a real
#               install is present, so finding it is itself a positive
#               signal that Python is genuinely available)
#   - python:   last-resort fallback (may still be the Store stub on
#               Windows; we accept it because on macOS/Linux it's
#               typically a real interpreter and a generic fallback is
#               better than nothing)
#
# The detection is split by `OS=Windows_NT` because `command -v` is a
# bash builtin and doesn't exist on `cmd.exe`; on Windows we use `where`
# (cmd.exe / PowerShell builtin), elsewhere `command -v`. `firstword`
# trims `where`'s multi-line output to the first hit.
# Prefer the project virtualenv (it has ruff/pytest/etc.) so `make lint/test/
# check` work without activating it first; otherwise fall back to the
# cross-platform interpreter detection. (venv/bin is POSIX; on Windows the
# wildcard misses and we use the py launcher branch.)
ifneq ($(wildcard venv/bin/python),)
  PYTHON := venv/bin/python
else ifeq ($(OS),Windows_NT)
  PYTHON := $(firstword $(shell where py 2>nul) $(shell where python3 2>nul) $(shell where python 2>nul))
else
  PYTHON := $(firstword $(shell command -v python3 2>/dev/null) $(shell command -v python 2>/dev/null))
endif

# Macro emitted at the top of clean targets — fails fast with a
# self-explanatory error if Python isn't reachable. `$(error ...)` is
# evaluated at parse time, so we wrap it in `ifeq` to gate it on the
# specific target's prerequisites.
PYTHON_NOT_FOUND_MSG := Python 3.10+ not found.\n  Install from https://www.python.org/ (Linux/macOS may use the system package manager).\n  On Windows: the Microsoft Store stub at %LOCALAPPDATA%\\Microsoft\\WindowsApps\\python.exe is NOT a real Python — open Settings > Apps > Apps & Features > App execution aliases and disable 'python.exe' / 'python3.exe', then install Python from python.org.

# ─── Why every compose call carries --env-file .env ──────────────────
# Docker Compose resolves ${VAR} INTERPOLATION from the .env in the PROJECT
# DIRECTORY, which defaults to the directory holding the compose file --
# infra/docker/ here, where no .env exists. `env_file:` on a service is a
# different mechanism with an explicit relative path (../../.env) and does find
# the repo-root file.
#
# So the stack silently ran on two different credential sources: services with
# `env_file:` (api, workers) got the real .env values, while every ${VAR:-default}
# in the compose files -- POSTGRES_USER/PASSWORD/DB, REDIS_PASSWORD,
# NEXT_PUBLIC_API_URL -- fell back to its literal default. The two halves agree
# only for as long as .env still contains the defaults; set a real
# POSTGRES_PASSWORD and postgres keeps `nis2secret` while the API connects with
# the new one. Observed: the whole dev stack up, postgres "healthy", and every
# request failing with `password authentication failed`.
#
# Worse in prod, where the guards are `${POSTGRES_PASSWORD:?...}` rather than
# `:-default`: with no interpolation source the guard fires and compose refuses
# the file outright, so `make prod` could not start the stack at all. Nothing
# caught it because no CI job builds or boots the images.
#
# --env-file .env points interpolation at the repo-root file, making the two
# mechanisms agree. Verified by test_compose_env_wiring.py.

# Development
dev: dev-up
	@echo ""
	@echo "  NIS2 Platform: http://localhost:8077"
	@echo "  API docs:      http://localhost:8000/docs"
	@echo "  API health:    http://localhost:8000/api/v1/health"
	@echo ""

# `--wait` (compose v2.20+) blocks until every service is either
# `running` or, where a healthcheck is declared, `healthy`. Without it
# `make dev` returns the moment the daemon accepts the spec — the user
# sees the URLs and visits them while postgres is still booting and
# the API is still doing RLS bootstrap. The first 10–30 seconds then
# look like a broken stack ("Loading…", 502 Bad Gateway), and we burn
# trust on what is actually a startup race. `--wait-timeout 90` caps
# that wait at 90s so a genuinely stuck service still surfaces.
dev-up:
	docker compose --env-file .env -f infra/docker/docker-compose.dev.yml up -d --build --wait --wait-timeout 90

# `--renew-anon-volumes` is necessary whenever a node dependency was
# added or removed in packages/web. Docker compose preserves anonymous
# volumes (`- /app/node_modules` in the dev compose) across recreates;
# without renewing, the container keeps using the old install and the
# new package shows up as `Module not found` even after `--build`. This
# target is the right thing to run after editing package.json.
dev-up-fresh:
	docker compose --env-file .env -f infra/docker/docker-compose.dev.yml up -d --build --force-recreate --renew-anon-volumes --wait --wait-timeout 120

dev-down:
	docker compose --env-file .env -f infra/docker/docker-compose.dev.yml down

dev-logs:
	docker compose --env-file .env -f infra/docker/docker-compose.dev.yml logs -f

api-logs:
	docker compose --env-file .env -f infra/docker/docker-compose.dev.yml logs -f api

web-logs:
	docker compose --env-file .env -f infra/docker/docker-compose.dev.yml logs -f web

# Database
db-migrate:
	docker compose --env-file .env -f infra/docker/docker-compose.dev.yml exec api alembic revision --autogenerate -m "$(msg)"

# Re-encrypt every field-level secret under the current DATA_ENCRYPTION_KEY.
# Run this DURING a key rotation, with the old key in
# DATA_ENCRYPTION_KEY_PREVIOUS — see docs/guide/secrets-rotation.md. Without it,
# rotating the key silently locks out every MFA-enrolled user.
.PHONY: reencrypt reencrypt-dry-run
reencrypt-dry-run:
	docker compose --env-file .env -f infra/docker/docker-compose.prod.yml exec -T api python -m scripts.reencrypt --dry-run

reencrypt:
	docker compose --env-file .env -f infra/docker/docker-compose.prod.yml exec -T api python -m scripts.reencrypt

db-upgrade:
	docker compose --env-file .env -f infra/docker/docker-compose.dev.yml exec api alembic upgrade head

# P0-01: mark an EXISTING database as up-to-date with the current
# Alembic head. Run this ONCE when adopting Alembic on a database
# that was previously managed by ensure_schema().
db-stamp:
	docker compose --env-file .env -f infra/docker/docker-compose.dev.yml exec api alembic stamp head

db-history:
	docker compose --env-file .env -f infra/docker/docker-compose.dev.yml exec api alembic history --verbose

db-seed:
	docker compose --env-file .env -f infra/docker/docker-compose.dev.yml exec api python -m scripts.seed

# Provision the nis2_app least-privilege runtime role on an EXISTING database.
#
# infra/docker/initdb/ runs only on FIRST initialisation of an empty volume, so
# a deployment that predates the role never gets it. Symptom after upgrading:
# the API refuses to start with "production deploy with a SUPERUSER/BYPASSRLS
# app role" — which is correct, because until this role exists every RLS policy
# on that database is decorative.
#
# Idempotent: re-running it on a database that already has nis2_app is a no-op.
# Applies the same SQL the initdb wrapper does, as the bootstrap superuser.
db-provision-app-role:
	@test -f .env || (echo "ERROR: .env is missing" && exit 1)
	@grep -qE '^NIS2_APP_PASSWORD=.+' .env || ( \
	  echo "ERROR -- NIS2_APP_PASSWORD is not set in .env"; \
	  echo ""; \
	  echo "  It must match the password embedded in DATABASE_URL. Generate one:"; \
	  echo ""; \
	  echo "      openssl rand -base64 24"; \
	  echo ""; \
	  exit 1 )
	@echo "== provisioning nis2_app on the running postgres service =="
	@set -a; . ./.env; set +a; \
	  docker compose --env-file .env -f infra/docker/docker-compose.prod.yml exec -T postgres \
	    psql -v ON_ERROR_STOP=1 \
	         --username "$${POSTGRES_USER:-nis2}" \
	         --dbname "$${POSTGRES_DB:-nis2}" \
	         -v app_pw="$$NIS2_APP_PASSWORD" \
	    < infra/docker/initdb/sql/01-create-app-role.sql
	@echo ""
	@echo "  nis2_app provisioned (NOSUPERUSER NOBYPASSRLS, DML only)."
	@echo "  Point DATABASE_URL / DATABASE_URL_SYNC at it and keep the"
	@echo "  superuser in MIGRATION_DATABASE_URL, then restart the API."
	@echo ""

# ─── Versioning ──────────────────────────────────────────────────────
# `VERSION` at the repo root is the single source of truth. Four manifests and
# SECURITY.md's supported-versions table are derived from it by `version-set`,
# and `version-check` fails the build when any of them drifts.
#
# Everything this guards had already gone wrong: the manifests said 2.6.10 while
# the newest tag was v2.6.8 (so the README's release badge, which reads GitHub
# releases, showed a version two behind), CHANGELOG.md was missing entries for
# eight tagged releases, and SECURITY.md named 2.5.x as current for the whole
# 2.6 series while telling operators on 2.4.x they were still supported.

version:
ifeq ($(strip $(PYTHON)),)
	$(error $(PYTHON_NOT_FOUND_MSG))
endif
	@$(PYTHON) scripts/version.py current

version-check:
ifeq ($(strip $(PYTHON)),)
	$(error $(PYTHON_NOT_FOUND_MSG))
endif
	@$(PYTHON) scripts/version.py check

# Adds the git-tag requirement. Run before cutting a release, not on every commit:
# between releases the tree is legitimately ahead of the newest tag.
version-check-release:
ifeq ($(strip $(PYTHON)),)
	$(error $(PYTHON_NOT_FOUND_MSG))
endif
	@$(PYTHON) scripts/version.py check --release

# make version-set VERSION=2.7.0
version-set:
ifeq ($(strip $(PYTHON)),)
	$(error $(PYTHON_NOT_FOUND_MSG))
endif
	@test -n "$(VERSION)" || ( \
	  echo "ERROR -- pass the new version, e.g.  make version-set VERSION=2.7.0"; \
	  exit 1 )
	@$(PYTHON) scripts/version.py set $(VERSION)

# Testing
test: test-scanner test-api

test-scanner:
ifeq ($(strip $(PYTHON)),)
	$(error $(PYTHON_NOT_FOUND_MSG))
endif
	cd packages/scanner && $(PYTHON) -m pytest tests/ -v

test-api:
ifeq ($(strip $(PYTHON)),)
	$(error $(PYTHON_NOT_FOUND_MSG))
endif
	cd packages/api && $(PYTHON) -m pytest tests/ -v

# ─── Static checks (mirror CI; no running stack needed) ──────────────
lint:
ifeq ($(strip $(PYTHON)),)
	$(error $(PYTHON_NOT_FOUND_MSG))
endif
	$(PYTHON) -m ruff check packages/scanner/ --select=E,W,F --ignore=E501
	$(PYTHON) -m ruff check packages/api/ --select=E,W,F --ignore=E501
	$(PYTHON) -m ruff check scripts/ --select=E,W,F --ignore=E501

# `check` = the CI gates that need no database: lint, the policy greps, and the
# dependency audits. pip-audit is best-effort (skipped if not installed).
check: lint
	@echo "== policy: no bare 'except:' =="
	@! grep -rn "^[[:space:]]*except:$$" --include="*.py" packages/ || (echo "  FAIL" && exit 1)
	@echo "== policy: no CORS wildcard =="
	@! grep -q 'allow_origins=\["\*"\]' packages/api/app/main.py || (echo "  FAIL" && exit 1)
	@echo "== version consistency =="
	@$(PYTHON) scripts/version.py check
	@echo "== policy: .env not tracked =="
	@! git ls-files --error-unmatch .env 2>/dev/null || (echo "  FAIL: .env is tracked" && exit 1)
	@echo "== web lint + typecheck =="
	cd packages/web && npm run lint && npm run typecheck
	@echo "== npm audit (web, prod deps, high) =="
	cd packages/web && npm audit --omit=dev --audit-level=high
	@command -v pip-audit >/dev/null 2>&1 && pip-audit --skip-editable || echo "  (pip-audit not installed — skipped)"
	@echo "  static checks: OK"

# ─── Tests that need the running dev stack (`make dev-up`) ────────────
# Integration suite as the non-superuser nis2_app role on a dedicated nis2_test
# DB (so RLS is actually enforced). See scripts/test_integration.sh.
test-integration:
	bash scripts/test_integration.sh

# E2E live suite against the local stack. See scripts/test_e2e.sh.
test-e2e:
	bash scripts/test_e2e.sh

# Next.js production build.
test-web:
	cd packages/web && npm run build

# Prove Postgres RLS tenant isolation under nis2_app. See scripts/h5_validate.sh.
h5-validate:
	bash scripts/h5_validate.sh

# One-shot local mirror of CI: static checks + unit suites first (fast, no
# stack), then bring the stack up and run the stack-bound suites.
verify: check test-scanner test-api test-web dev-up test-integration test-e2e
	@echo ""
	@echo "  LOCAL VERIFY: ALL GREEN"
	@echo "  (run 'make h5-validate' for the RLS isolation proof on seeded data)"
	@echo ""

# ─── Production ──────────────────────────────────────────────────────
prod: prod-up

# v2.4.28: pre-flight check on `.env` before docker-compose touches the
# stack. Pre-2.4.28 a missing `.env` (or one with empty
# POSTGRES_PASSWORD / placeholder JWT_SECRET) made docker-compose exit
# with a generic "container is unhealthy" because Postgres refused to
# initialise — the actual root cause was buried in `docker logs
# postgres-1` which 99% of operators never look at. This target turns
# that silent failure into a loud, actionable error before any
# container is created. Reported by Davide
prod-preflight:
	@test -f .env || ( \
	  echo ""; \
	  echo "==================================================================="; \
	  echo "  ERROR -- .env is missing"; \
	  echo "==================================================================="; \
	  echo ""; \
	  echo "  Step 1) Copy the example file:"; \
	  echo ""; \
	  echo "      cp .env.example .env"; \
	  echo ""; \
	  echo "  Step 2) Open .env in an editor and set these variables:"; \
	  echo ""; \
	  echo "      POSTGRES_PASSWORD   (any non-empty string)"; \
	  echo "      REDIS_PASSWORD      (any non-empty string)"; \
	  echo "      JWT_SECRET          (run:  openssl rand -base64 32 )"; \
	  echo "      NIS2_APP_PASSWORD   (runtime DB role; must match DATABASE_URL)"; \
	  echo "      CORS_ORIGINS        (comma-separated, no wildcards)"; \
	  echo "                          example:  https://nis2.example.com"; \
	  echo "      DOMAIN              (your public host for Caddy HTTPS)"; \
	  echo ""; \
	  echo "  Step 3) Re-run:  make prod"; \
	  echo ""; \
	  exit 1 )
	@grep -qE '^POSTGRES_PASSWORD=.+' .env || ( \
	  echo ""; \
	  echo "==================================================================="; \
	  echo "  ERROR -- POSTGRES_PASSWORD is missing or empty in .env"; \
	  echo "==================================================================="; \
	  echo ""; \
	  echo "  Postgres refuses to initialise without a password."; \
	  echo ""; \
	  echo "  Set any non-empty string in .env, for example:"; \
	  echo ""; \
	  echo "      POSTGRES_PASSWORD=$$(openssl rand -base64 24)"; \
	  echo ""; \
	  exit 1 )
	@if grep -iqE '^(POSTGRES_PASSWORD|NIS2_APP_PASSWORD|REDIS_PASSWORD|JWT_SECRET|DATA_ENCRYPTION_KEY|SMTP_PASSWORD)=.*(change_me|change-me|changeme|generate_me|generate-me|generateme|placeholder|yourdomain|your_|insert_|replace_)' .env; then \
	  echo ""; \
	  echo "==================================================================="; \
	  echo "  ERROR -- one or more secrets in .env are still placeholders"; \
	  echo "==================================================================="; \
	  echo ""; \
	  echo "  Offending lines (value redacted):"; \
	  echo ""; \
	  grep -inE '^(POSTGRES_PASSWORD|NIS2_APP_PASSWORD|REDIS_PASSWORD|JWT_SECRET|DATA_ENCRYPTION_KEY|SMTP_PASSWORD)=.*(change_me|change-me|changeme|generate_me|generate-me|generateme|placeholder|yourdomain|your_|insert_|replace_)' .env \
	    | sed -E 's/=.*/=<PLACEHOLDER>/' | sed 's/^/      /'; \
	  echo ""; \
	  echo "  These are the literal values published in .env.example. A"; \
	  echo "  deployment that keeps them is running on credentials that"; \
	  echo "  anyone can read in the public repository -- for JWT_SECRET"; \
	  echo "  that means anyone can mint a valid token for any user in any"; \
	  echo "  organisation."; \
	  echo ""; \
	  echo "  This check used to look for the literal 'GENERATE_ME' only."; \
	  echo "  v2.5.5 renamed the placeholders to 'CHANGE_ME_*' and the check"; \
	  echo "  silently stopped matching anything. It is now marker-based, and"; \
	  echo "  packages/api/tests/test_env_example_placeholders.py asserts that"; \
	  echo "  every value shipped in .env.example is still caught."; \
	  echo ""; \
	  echo "  Generate a real secret per line:"; \
	  echo ""; \
	  echo "      openssl rand -base64 32"; \
	  echo ""; \
	  exit 1; fi
	@grep -qE '^JWT_SECRET=.{32,}' .env || ( \
	  echo ""; \
	  echo "==================================================================="; \
	  echo "  ERROR -- JWT_SECRET in .env is shorter than 32 characters"; \
	  echo "==================================================================="; \
	  echo ""; \
	  echo "  The API refuses to start in production with a short secret."; \
	  echo ""; \
	  echo "  Generate one and paste it into .env:"; \
	  echo ""; \
	  echo "      openssl rand -base64 32"; \
	  echo ""; \
	  exit 1 )
	@grep -qE '^REDIS_PASSWORD=.+' .env || ( \
	  echo ""; \
	  echo "==================================================================="; \
	  echo "  ERROR -- REDIS_PASSWORD is missing or empty in .env"; \
	  echo "==================================================================="; \
	  echo ""; \
	  echo "  Redis requires a password in production (--requirepass)."; \
	  echo ""; \
	  echo "  Set any non-empty string in .env, for example:"; \
	  echo ""; \
	  echo "      REDIS_PASSWORD=$$(openssl rand -base64 24)"; \
	  echo ""; \
	  exit 1 )
	@if grep -qE '^REDIS_PASSWORD=changeme$$' .env; then \
	  echo ""; \
	  echo "==================================================================="; \
	  echo "  ERROR -- REDIS_PASSWORD is still the default 'changeme'"; \
	  echo "==================================================================="; \
	  echo ""; \
	  echo "  Replace it with a strong password:"; \
	  echo ""; \
	  echo "      REDIS_PASSWORD=$$(openssl rand -base64 24)"; \
	  echo ""; \
	  exit 1; fi
	@grep -qE '^CORS_ORIGINS=.+' .env || ( \
	  echo ""; \
	  echo "==================================================================="; \
	  echo "  ERROR -- CORS_ORIGINS is missing or empty in .env"; \
	  echo "==================================================================="; \
	  echo ""; \
	  echo "  The API refuses to start without an explicit allow-list."; \
	  echo ""; \
	  echo "  Example for a single front-end domain:"; \
	  echo ""; \
	  echo "      CORS_ORIGINS=https://nis2.example.com"; \
	  echo ""; \
	  echo "  Multiple domains: comma-separated, NO wildcards."; \
	  echo ""; \
	  exit 1 )
	@if grep -qE '^ENVIRONMENT=development' .env; then \
	  echo ""; \
	  echo "==================================================================="; \
	  echo "  ERROR -- ENVIRONMENT=development in a production .env"; \
	  echo "==================================================================="; \
	  echo ""; \
	  echo "  docker-compose.prod.yml now pins ENVIRONMENT=production per"; \
	  echo "  service, so THIS STACK is safe regardless. But the line is still"; \
	  echo "  wrong, and anything that reads .env directly -- systemd, k8s,"; \
	  echo "  bare uvicorn, alembic, a host-side pytest run -- will pick up"; \
	  echo "  development mode, which:"; \
	  echo ""; \
	  echo "    * drops the Secure flag from the session cookies;"; \
	  echo "    * mounts the UNAUTHENTICATED /api/v1/auth/debug/last-email"; \
	  echo "      endpoint, which returns the last password-reset link and"; \
	  echo "      is enough on its own for account takeover;"; \
	  echo "    * skips the JWT_SECRET / CORS_ORIGINS boot validation;"; \
	  echo "    * skips the SUPERUSER/BYPASSRLS refusal, making RLS decorative;"; \
	  echo "    * swallows every outbound email into an in-memory outbox."; \
	  echo ""; \
	  echo "  Fix:"; \
	  echo ""; \
	  echo "      ENVIRONMENT=production"; \
	  echo ""; \
	  exit 1; fi
	@if grep -iqE '^ENABLE_DEV_EMAIL_DEBUG=(1|true|yes|on)' .env; then \
	  echo ""; \
	  echo "==================================================================="; \
	  echo "  ERROR -- ENABLE_DEV_EMAIL_DEBUG is enabled"; \
	  echo "==================================================================="; \
	  echo ""; \
	  echo "  This mounts GET /api/v1/auth/debug/last-email, which returns the"; \
	  echo "  last outbound email -- password-reset link included -- to any"; \
	  echo "  unauthenticated caller. Together with the public forgot-password"; \
	  echo "  endpoint that is a complete account-takeover chain against every"; \
	  echo "  user on the instance."; \
	  echo ""; \
	  echo "  The API already refuses to boot in production with this set; the"; \
	  echo "  check is repeated here so you get a message instead of a"; \
	  echo "  restart-looping container."; \
	  echo ""; \
	  echo "  It is a development-only helper for the e2e suite."; \
	  echo "  docker-compose.dev.yml sets it for you. Remove it from .env:"; \
	  echo ""; \
	  echo "      ENABLE_DEV_EMAIL_DEBUG=false"; \
	  echo ""; \
	  exit 1; fi
	@if grep -qE '^DOMAIN=nis2\.yourdomain\.com' .env; then \
	  echo ""; \
	  echo "==================================================================="; \
	  echo "  ERROR -- DOMAIN is still the placeholder nis2.yourdomain.com"; \
	  echo "==================================================================="; \
	  echo ""; \
	  echo "  Caddy would request a public certificate for a domain you do"; \
	  echo "  not control: the ACME challenge fails and repeated attempts"; \
	  echo "  burn the Let's Encrypt failure rate limit for your IP."; \
	  echo ""; \
	  echo "  Set your real public host:"; \
	  echo ""; \
	  echo "      DOMAIN=nis2.example.com"; \
	  echo ""; \
	  echo "  Or, for a local production smoke test, use:"; \
	  echo ""; \
	  echo "      DOMAIN=localhost"; \
	  echo ""; \
	  exit 1; fi
	@grep -qE '^SMTP_HOST=.+' .env || ( \
	  echo ""; \
	  echo "==================================================================="; \
	  echo "  WARNING -- SMTP_HOST is empty"; \
	  echo "==================================================================="; \
	  echo ""; \
	  echo "  In production the in-memory dev outbox is OFF, so nothing will"; \
	  echo "  send mail. Two flows go silent:"; \
	  echo ""; \
	  echo "    * password reset -- users never receive the link;"; \
	  echo "    * Art. 23 incident-deadline alerts -- the 24h/72h/1-month"; \
	  echo "      fallback channel is 'email the org admins'."; \
	  echo ""; \
	  echo "  The API stays up and still returns 204; the failure appears"; \
	  echo "  only in the logs. Configure SMTP_* in .env, or accept that"; \
	  echo "  both flows are inert on this deployment."; \
	  echo "" )
	@grep -qE '^PUBLIC_URL=https?://localhost' .env && ( \
	  echo ""; \
	  echo "==================================================================="; \
	  echo "  WARNING -- PUBLIC_URL still points at localhost"; \
	  echo "==================================================================="; \
	  echo ""; \
	  echo "  Password-reset emails embed this origin. Recipients would get a"; \
	  echo "  link they cannot open. Set it to your public origin, e.g."; \
	  echo ""; \
	  echo "      PUBLIC_URL=https://nis2.example.com"; \
	  echo "" ) || true
	@if grep -qE '^RLS_SUPERUSER_OK=1' .env; then \
	  echo ""; \
	  echo "==================================================================="; \
	  echo "  WARNING -- RLS_SUPERUSER_OK=1 is set in .env"; \
	  echo "==================================================================="; \
	  echo ""; \
	  echo "  This opts out of the v2.5.1 production safety check that refuses"; \
	  echo "  to start when the DB role is SUPERUSER / BYPASSRLS -- i.e. when"; \
	  echo "  Postgres RLS is decorative. Tenant isolation will rely on"; \
	  echo "  application-layer filters ONLY."; \
	  echo ""; \
	  echo "  Remove the line and provision a non-superuser app role before"; \
	  echo "  going live, for example:"; \
	  echo ""; \
	  echo "      ALTER ROLE <app_role> NOSUPERUSER NOBYPASSRLS;"; \
	  echo ""; fi
	@echo ""
	@echo "  .env preflight: OK"
	@echo ""

prod-up: prod-preflight
	docker compose --env-file .env -f infra/docker/docker-compose.prod.yml up -d --build --wait --wait-timeout 120

prod-down:
	docker compose --env-file .env -f infra/docker/docker-compose.prod.yml down

# ─── Cleanup ─────────────────────────────────────────────────────────
# Drops dev volumes (postgres data, etc.) and Python/Next caches.
# Safe to re-run; preserves images and node_modules so the next `make dev`
# still uses Docker's layer cache and skips `npm ci`.
#
# The work is delegated to scripts/clean.py because the previous shell
# pipeline (`find -exec ... 2>/dev/null || true`) doesn't run on Windows
# cmd.exe — `find`, `xargs`, the redirect, and `|| true` all expand to
# nothing or to errors. Reported by Davide on Windows native.
clean:
ifeq ($(strip $(PYTHON)),)
	$(error $(PYTHON_NOT_FOUND_MSG))
endif
	$(PYTHON) scripts/clean.py

# Nuclear cleanup — what you reach for when "weird stale state" is the
# diagnosis and you want a guaranteed-fresh first run. Drops everything
# `clean` does plus host node_modules, the prod stack, and the per-project
# Docker images. The next `make dev` will refetch and rebuild from scratch.
clean-all:
ifeq ($(strip $(PYTHON)),)
	$(error $(PYTHON_NOT_FOUND_MSG))
endif
	$(PYTHON) scripts/clean.py --all
