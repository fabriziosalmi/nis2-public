# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public

.PHONY: dev dev-up dev-up-fresh dev-down dev-logs api-logs web-logs db-migrate db-upgrade db-seed test test-api test-scanner lint clean clean-all prod prod-preflight prod-up prod-down

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
ifeq ($(OS),Windows_NT)
  PYTHON := $(firstword $(shell where py 2>nul) $(shell where python3 2>nul) $(shell where python 2>nul))
else
  PYTHON := $(firstword $(shell command -v python3 2>/dev/null) $(shell command -v python 2>/dev/null))
endif

# Macro emitted at the top of clean targets — fails fast with a
# self-explanatory error if Python isn't reachable. `$(error ...)` is
# evaluated at parse time, so we wrap it in `ifeq` to gate it on the
# specific target's prerequisites.
PYTHON_NOT_FOUND_MSG := Python 3.10+ not found.\n  Install from https://www.python.org/ (Linux/macOS may use the system package manager).\n  On Windows: the Microsoft Store stub at %LOCALAPPDATA%\\Microsoft\\WindowsApps\\python.exe is NOT a real Python — open Settings > Apps > Apps & Features > App execution aliases and disable 'python.exe' / 'python3.exe', then install Python from python.org.

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
	docker compose -f infra/docker/docker-compose.dev.yml up -d --build --wait --wait-timeout 90

# `--renew-anon-volumes` is necessary whenever a node dependency was
# added or removed in packages/web. Docker compose preserves anonymous
# volumes (`- /app/node_modules` in the dev compose) across recreates;
# without renewing, the container keeps using the old install and the
# new package shows up as `Module not found` even after `--build`. This
# target is the right thing to run after editing package.json.
dev-up-fresh:
	docker compose -f infra/docker/docker-compose.dev.yml up -d --build --force-recreate --renew-anon-volumes --wait --wait-timeout 120

dev-down:
	docker compose -f infra/docker/docker-compose.dev.yml down

dev-logs:
	docker compose -f infra/docker/docker-compose.dev.yml logs -f

api-logs:
	docker compose -f infra/docker/docker-compose.dev.yml logs -f api

web-logs:
	docker compose -f infra/docker/docker-compose.dev.yml logs -f web

# Database
db-migrate:
	docker compose -f infra/docker/docker-compose.dev.yml exec api alembic revision --autogenerate -m "$(msg)"

db-upgrade:
	docker compose -f infra/docker/docker-compose.dev.yml exec api alembic upgrade head

db-seed:
	docker compose -f infra/docker/docker-compose.dev.yml exec api python -m scripts.seed

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
	@test -f .env || ( echo ""; \
	  echo "ERROR: .env file is missing."; \
	  echo "  $$ cp .env.example .env"; \
	  echo "  Then edit .env and set:"; \
	  echo "    - POSTGRES_PASSWORD  (any non-empty string; rotate before sharing infra)"; \
	  echo "    - JWT_SECRET         (run: openssl rand -base64 32)"; \
	  echo "    - NEXTAUTH_SECRET    (run: openssl rand -base64 32)"; \
	  echo "    - REDIS_PASSWORD     (any non-empty string)"; \
	  echo "    - CORS_ORIGINS       (comma-separated allow-list, no wildcards)"; \
	  echo "    - DOMAIN             (your public hostname for Caddy auto-HTTPS)"; \
	  echo ""; exit 1 )
	@grep -qE '^POSTGRES_PASSWORD=.+' .env || ( echo ""; \
	  echo "ERROR: POSTGRES_PASSWORD is missing or empty in .env."; \
	  echo "Postgres will refuse to initialise without a non-empty password."; \
	  echo ""; exit 1 )
	@if grep -qE '^JWT_SECRET=GENERATE_ME' .env; then echo ""; \
	  echo "ERROR: JWT_SECRET in .env is still the placeholder 'GENERATE_ME...'."; \
	  echo "Generate a real one:"; \
	  echo "  $$ openssl rand -base64 32"; \
	  echo "and replace the JWT_SECRET= line in .env."; \
	  echo ""; exit 1; fi
	@grep -qE '^JWT_SECRET=.{32,}' .env || ( echo ""; \
	  echo "ERROR: JWT_SECRET in .env is shorter than 32 characters."; \
	  echo "The API refuses to start in production with a short secret."; \
	  echo "Generate one with: openssl rand -base64 32"; \
	  echo ""; exit 1 )
	@grep -qE '^CORS_ORIGINS=.+' .env || ( echo ""; \
	  echo "ERROR: CORS_ORIGINS is missing or empty in .env."; \
	  echo "The API refuses to start in production without an explicit allow-list."; \
	  echo "Example: CORS_ORIGINS=https://nis2.example.com"; \
	  echo ""; exit 1 )
	@echo "  .env preflight: OK"

prod-up: prod-preflight
	docker compose -f infra/docker/docker-compose.prod.yml up -d --build --wait --wait-timeout 120

prod-down:
	docker compose -f infra/docker/docker-compose.prod.yml down

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
