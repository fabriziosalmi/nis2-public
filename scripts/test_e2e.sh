#!/usr/bin/env bash
# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
#
# Run the E2E live suite (test_e2e_live.py) against the running dev stack.
# Waits for API health, ensures the E2E user exists, then runs pytest. Mirrors
# the ci.yml "e2e-tests" job but points at the local stack. Requires `make dev-up`.
#
#   bash scripts/test_e2e.sh [extra pytest args]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BASE="${E2E_LIVE_BASE_URL:-http://localhost:8000}"
EMAIL="${E2E_LIVE_EMAIL:-e2e-ci@example.com}"
PW="${E2E_LIVE_PASSWORD:-E2eC!password99}"
PY="$ROOT/venv/bin/python"; [ -x "$PY" ] || PY="$(command -v python3)"

echo "== wait for API health @ $BASE =="
for _ in $(seq 1 30); do curl -sf "$BASE/api/v1/health" >/dev/null 2>&1 && break || sleep 1; done
curl -sf "$BASE/api/v1/health" >/dev/null || { echo "API not healthy at $BASE — run 'make dev-up'"; exit 1; }

echo "== ensure E2E user exists (201 created / 409 already there) =="
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/api/v1/auth/register" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PW\",\"full_name\":\"E2E CI User\",\"org_name\":\"E2E CI Org\"}" || true)
echo "  register: $HTTP_CODE"

# If running against the local docker stack, ensure canonical password/MFA state in case a prior run aborted mid-rotation
if command -v docker >/dev/null 2>&1 && [ -f "$ROOT/infra/docker/docker-compose.dev.yml" ] && [ -f "$ROOT/.env" ]; then
  docker compose --env-file "$ROOT/.env" -f "$ROOT/infra/docker/docker-compose.dev.yml" exec -T postgres \
    psql -U nis2 -d nis2 -c "UPDATE users SET password_hash = '\$2b\$12\$PTjcP8rtc9.1RrpEd.f7cOauq90W1m0Emaonq6s3WnwhwUOiC5qoO', totp_enabled = false, totp_secret = NULL, password_changed_at = NULL WHERE email='$EMAIL';" >/dev/null 2>&1 || true
fi

# Reset rate limits & throttle state before running the live suite
curl -sf -X POST "$BASE/api/v1/auth/debug/reset-rate-limit?email=$EMAIL" >/dev/null 2>&1 || true

echo "== run E2E live suite =="
cd packages/api
E2E_LIVE_BASE_URL="$BASE" E2E_LIVE_EMAIL="$EMAIL" E2E_LIVE_PASSWORD="$PW" \
  ENVIRONMENT=development ENABLE_DEV_EMAIL_DEBUG=true PYTHONPATH=. \
  "$PY" -m pytest tests/test_e2e_live.py "${@:--q}"
