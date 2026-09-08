#!/bin/sh
# P0-01 audit fix: production entrypoint that runs Alembic migrations
# before starting the application server.
#
# Usage (in docker-compose):
#   command: /app/packages/api/entrypoint.sh gunicorn app.main:app ...
#
# On a fresh database this creates all 17 tables. On an existing one
# it applies only the pending revisions (no-op if already at head).
# The `ensure_schema()` fallback in database.py is still called at
# lifespan startup, but this runs first and is the authoritative path.
#
# Migrations only run when the first argument is uvicorn or gunicorn
# (the API server). Celery workers and beat skip migrations — they
# depend on the API service which runs first and applies the schema.

set -e

case "$1" in
    *uvicorn*|*gunicorn*)
        echo "[entrypoint] Running Alembic migrations..."
        # Exit on failure. This used to log a warning and carry on, letting the
        # lifespan's create_all fallback patch whatever it could — so a
        # deployment whose migration failed came up serving traffic on a schema
        # that matched neither the previous release nor the new one, and
        # reported itself healthy while doing it. The only evidence was a
        # WARNING line in a container log.
        #
        # Failing here is the behaviour an operator expects from a failed
        # upgrade: with `restart: unless-stopped` the container retries, and
        # because dependants gate on the API being healthy, the deployment holds
        # instead of routing traffic at an unknown schema.
        if ! python -m alembic upgrade head 2>&1; then
            echo "[entrypoint] FATAL: alembic upgrade failed — refusing to start."
            echo "[entrypoint] The database schema is not at head. Fix the migration"
            echo "[entrypoint] or restore from backup; do not run the API against it."
            exit 1
        fi
        ;;
    *)
        echo "[entrypoint] Non-API process detected ($1) — skipping migrations"
        ;;
esac

echo "[entrypoint] Starting: $@"
exec "$@"
