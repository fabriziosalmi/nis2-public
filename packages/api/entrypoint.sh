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
        python -m alembic upgrade head 2>&1 || {
            echo "[entrypoint] WARNING: alembic upgrade failed — falling back to ensure_schema()"
            # Don't exit; ensure_schema() in the lifespan will try create_all.
        }
        ;;
    *)
        echo "[entrypoint] Non-API process detected ($1) — skipping migrations"
        ;;
esac

echo "[entrypoint] Starting: $@"
exec "$@"
