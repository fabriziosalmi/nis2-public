#!/bin/bash
# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
#
# Provision the least-privilege application role on first volume init.
#
# WHY THIS WRAPPER EXISTS
# -----------------------
# sql/01-create-app-role.sql needs the new role's password as the psql variable
# `app_pw`. The postgres image's /docker-entrypoint-initdb.d/ runner invokes
# .sql files with a plain `psql -f`, which has no way to pass `-v`. So the SQL
# sat in the repository, fully written and documented, mounted by nothing and
# executed by nobody — the least-privilege role it provisions was documented in
# the README as the security model and did not exist in any deployment.
#
# The runner DOES execute .sh files, and ignores subdirectories. Hence: this
# wrapper in the mounted root, the SQL one level down in sql/.
#
# Runs ONCE, on first initialisation of an empty data volume. For a database
# that already exists, this file never fires — use `make db-provision-app-role`,
# which applies the same SQL to a live volume.
set -euo pipefail

SQL_FILE="$(dirname "$0")/sql/01-create-app-role.sql"

if [ -z "${NIS2_APP_PASSWORD:-}" ]; then
    echo "[initdb] ERROR: NIS2_APP_PASSWORD is not set." >&2
    echo "[initdb] The nis2_app runtime role cannot be provisioned without it." >&2
    echo "[initdb] Postgres RLS is BYPASSED for superusers, so running the API" >&2
    echo "[initdb] as the bootstrap superuser makes every tenant-isolation" >&2
    echo "[initdb] policy decorative. Set NIS2_APP_PASSWORD in .env and" >&2
    echo "[initdb] recreate the volume, or run 'make db-provision-app-role'." >&2
    # Hard fail: a silently skipped security bootstrap is precisely the class of
    # problem this file was written to end. Failing here aborts initialisation
    # loudly instead of yielding a database the API will refuse to serve from
    # for reasons the operator would then have to reverse-engineer.
    exit 1
fi

echo "[initdb] Provisioning least-privilege app role nis2_app..."
psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname "$POSTGRES_DB" \
     -v app_pw="$NIS2_APP_PASSWORD" \
     -f "$SQL_FILE"
echo "[initdb] nis2_app provisioned (NOSUPERUSER NOBYPASSRLS, DML only)."
