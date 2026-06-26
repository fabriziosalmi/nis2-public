#!/usr/bin/env bash
# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
#
# H5 — validate Postgres RLS tenant isolation under the least-privilege app role.
#
# Provisions nis2_app (NOSUPERUSER NOBYPASSRLS) via the init-SQL, then proves the
# tenant_isolation policies actually filter for that role:
#   * no org context      -> 0 rows (policy denies)
#   * org A's context      -> only org A's rows
#   * org B's context      -> none of org A's rows (cross-tenant read refused)
#
# This is the proof that isolation rests on the database, not just the app-layer
# org_id filters. Run against the dev stack (`make dev-up`) with seeded data.
#
#   bash scripts/h5_validate.sh
#
# Env: NIS2_APP_PASSWORD (default h5validate), COMPOSE_FILE.
set -uo pipefail
cd "$(dirname "$0")/.."

COMPOSE_FILE="${COMPOSE_FILE:-infra/docker/docker-compose.dev.yml}"
APP_PW="${NIS2_APP_PASSWORD:-h5validate}"
DC=(docker compose -f "$COMPOSE_FILE")

su()  { "${DC[@]}" exec -T postgres psql -U nis2 -d nis2 -tAX -c "$1" | tail -1; }
# app() may run "SET ...; SELECT ..." in one session (the GUC must persist across
# the two statements); psql prints the SET command tag first, so keep only the
# final line — the SELECT's value.
app() { "${DC[@]}" exec -T -e PGPASSWORD="$APP_PW" postgres psql -U nis2_app -d nis2 -tAX -c "$1" | tail -1; }

fail=0
check() { # label  actual  expected
  if [ "$2" = "$3" ]; then printf '  \033[32mPASS\033[0m  %s (%s)\n' "$1" "$2"
  else printf '  \033[31mFAIL\033[0m  %s: got "%s" expected "%s"\n' "$1" "$2" "$3"; fail=1; fi
}

echo "== 1. Provision nis2_app (init-SQL, idempotent) =="
if "${DC[@]}" exec -T postgres psql -U nis2 -d nis2 -v app_pw="$APP_PW" \
      < infra/docker/initdb/01-create-app-role.sql >/tmp/h5_provision.log 2>&1; then
  echo "  provisioned"
else
  echo "  provision returned non-zero — last lines:"; tail -3 /tmp/h5_provision.log | sed 's/^/    /'
fi

echo "== 2. Role is least-privilege =="
check "nis2_app NOSUPERUSER NOBYPASSRLS" \
  "$(su "SELECT rolsuper::text||'/'||rolbypassrls::text FROM pg_roles WHERE rolname='nis2_app'")" "false/false"

echo "== 3. RLS isolation proof =="
ORG_A=$(su "SELECT organization_id FROM scans LIMIT 1")
if [ -z "$ORG_A" ]; then
  echo "  FAIL: no seeded scan to test against — run 'make db-seed' first"; exit 1
fi
# Prefer a real second org; fall back to a synthetic uuid (a 'tenant' that owns
# nothing) so the isolation proof still holds with single-org seed data.
ORG_B=$(su "SELECT id FROM organizations WHERE id <> '$ORG_A' LIMIT 1")
[ -z "$ORG_B" ] && ORG_B=$(su "SELECT gen_random_uuid()")
echo "  ORG_A (has scan) = $ORG_A"
echo "  ORG_B (other)    = $ORG_B"
A_SCANS=$(su "SELECT count(*) FROM scans    WHERE organization_id='$ORG_A'")
A_FIND=$(su  "SELECT count(*) FROM findings WHERE organization_id='$ORG_A'")

check "no-context scans=0"            "$(app 'SELECT count(*) FROM scans')"    "0"
check "no-context findings=0"         "$(app 'SELECT count(*) FROM findings')" "0"
check "orgA-context scans"            "$(app "SET app.current_org_id='$ORG_A'; SELECT count(*) FROM scans")"    "$A_SCANS"
check "orgA-context findings"         "$(app "SET app.current_org_id='$ORG_A'; SELECT count(*) FROM findings")" "$A_FIND"
check "orgB cannot see A's scans"     "$(app "SET app.current_org_id='$ORG_B'; SELECT count(*) FROM scans")"    "0"
check "orgB cannot see A's findings"  "$(app "SET app.current_org_id='$ORG_B'; SELECT count(*) FROM findings")" "0"

echo
if [ "$fail" = 0 ]; then echo "H5 RLS VALIDATION: ALL CHECKS PASSED ✅"; else echo "H5 RLS VALIDATION: FAILURES ABOVE ❌"; fi
exit $fail
