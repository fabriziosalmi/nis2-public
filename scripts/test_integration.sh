#!/usr/bin/env bash
# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
#
# Run the integration suite the way CI does: as the non-superuser, RLS-bound
# nis2_app role against a dedicated nis2_test database (so the RLS policies are
# actually enforced, not bypassed by a superuser). Mirrors the ci.yml
# "integration-tests" job. Requires the dev stack up (`make dev-up`).
#
#   bash scripts/test_integration.sh [extra pytest args]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

COMPOSE_FILE="${COMPOSE_FILE:-infra/docker/docker-compose.dev.yml}"
# Prefer the value in .env so we align with the role the postgres initdb wrapper
# already provisioned; fall back for a bare checkout.
APP_PW="${NIS2_APP_PASSWORD:-$(grep -E '^NIS2_APP_PASSWORD=' "$ROOT/.env" 2>/dev/null | cut -d= -f2- || true)}"
APP_PW="${APP_PW:-h5validate}"
PGPORT_HOST="${PGPORT_HOST:-5433}"
PY="$ROOT/venv/bin/python"; [ -x "$PY" ] || PY="$(command -v python3)"
psql_su() { docker compose --env-file "$ROOT/.env" -f "$COMPOSE_FILE" exec -T postgres psql -U nis2 "$@"; }

echo "== provision nis2_test + nis2_app (NOSUPERUSER NOBYPASSRLS) =="
psql_su -d nis2 -tAc "SELECT 1 FROM pg_database WHERE datname='nis2_test'" | grep -q 1 \
  || psql_su -d nis2 -c "CREATE DATABASE nis2_test"
# Create the role if absent, and ALWAYS set its password to the one this script
# will connect with. The create-only form broke as soon as the postgres initdb
# wrapper started provisioning nis2_app at volume init: the role then already
# existed with the password from .env, this script skipped creation, and every
# test errored with `password authentication failed for user "nis2_app"`.
# Aligning unconditionally makes the script independent of who created the role.
psql_su -d nis2 -tAc "SELECT 1 FROM pg_roles WHERE rolname='nis2_app'" | grep -q 1 \
  || psql_su -d nis2 -c "CREATE ROLE nis2_app WITH LOGIN NOSUPERUSER NOBYPASSRLS"
psql_su -d nis2 -c "ALTER ROLE nis2_app WITH LOGIN PASSWORD '$APP_PW' NOSUPERUSER NOBYPASSRLS" >/dev/null
# The suite runs Base.metadata.create_all itself, so the role needs DDL here
# (unlike the prod init-SQL role, which is DML-only).
psql_su -d nis2_test \
  -c "GRANT ALL ON SCHEMA public TO nis2_app" \
  -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO nis2_app" \
  -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO nis2_app" >/dev/null

echo "== run integration suite as nis2_app =="
cd packages/api
INTEGRATION_DB=1 ENVIRONMENT=development \
  JWT_SECRET='integration-test-secret-must-be-at-least-32-chars-long-yes' \
  CORS_ORIGINS='http://localhost:3000' \
  DATABASE_URL="postgresql+asyncpg://nis2_app:${APP_PW}@localhost:${PGPORT_HOST}/nis2_test" \
  DATABASE_URL_SYNC="postgresql://nis2_app:${APP_PW}@localhost:${PGPORT_HOST}/nis2_test" \
  PYTHONPATH=. "$PY" -m pytest tests/test_integration.py "${@:--q}"
