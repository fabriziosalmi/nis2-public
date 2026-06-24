# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Health endpoints.

Three tiers — each suitable for a different probe type:

  GET /health        — liveness. No dependencies checked. Returns 200 as
                       long as the Python process is alive and FastAPI is
                       routing. Used by Caddy's `health_uri` directive and
                       container runtimes (Docker HEALTHCHECK, k8s liveness).
                       Never returns a non-200 — if it does, the process is
                       dead and the orchestrator should restart it.

  GET /health/ready  — readiness. Checks database, Redis, and Celery worker
                       reachability. Returns 200 {"status":"ok"} when all
                       dependencies are healthy, or 503 {"status":"degraded"}
                       with per-check detail when any dependency is down.
                       Use this as the k8s readinessProbe or as the target
                       for an uptime monitor that should page on-call.

  GET /health/live   — alias for GET /health, kept for k8s naming conventions
                       where liveness and readiness probes have distinct paths.
"""

import logging

from fastapi import APIRouter, Depends, Response
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db

router = APIRouter(prefix="/health", tags=["health"])
logger = logging.getLogger(__name__)

# Celery worker ping timeout in seconds. We use a short timeout so a
# dead/slow worker pool doesn't hold the readiness probe open for 30 s.
_CELERY_PING_TIMEOUT = 3


@router.get("")
async def health() -> dict:
    """Liveness probe — always 200 if the process is running."""
    return {"status": "ok"}


@router.get("/live")
async def liveness() -> dict:
    """Explicit liveness alias (k8s convention)."""
    return {"status": "ok"}


@router.get("/ready")
async def readiness(
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Readiness probe — checks database, Redis, and Celery workers.

    Returns 200 when all checks pass, 503 when any check fails.
    The `checks` dict details which components are affected.
    """
    checks: dict[str, str] = {}

    # --- Database -----------------------------------------------------------
    try:
        await db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:
        logger.error("health/ready: database check failed: %s", exc)
        checks["database"] = "error"

    # --- Redis --------------------------------------------------------------
    try:
        import redis.asyncio as aioredis

        r = aioredis.from_url(settings.redis_url, decode_responses=True)
        await r.ping()
        await r.aclose()
        checks["redis"] = "ok"
    except Exception as exc:
        logger.error("health/ready: redis check failed: %s", exc)
        checks["redis"] = "error"

    # --- Celery workers -----------------------------------------------------
    # celery.control.inspect().ping() broadcasts a ping to all active
    # workers and waits up to _CELERY_PING_TIMEOUT seconds for replies.
    # A non-empty reply dict means at least one worker is alive.
    # We intentionally don't fail the probe if the result is empty —
    # workers may be temporarily between tasks (and Celery's inspect
    # channel is best-effort). We only mark "error" if the call itself
    # raises, which indicates the broker is unreachable.
    try:
        from app.tasks.celery_app import celery_app

        inspector = celery_app.control.inspect(timeout=_CELERY_PING_TIMEOUT)
        # inspect() calls are synchronous (they use the Kombu transport
        # directly). Run in a thread to avoid blocking the event loop.
        import asyncio

        replies = await asyncio.get_running_loop().run_in_executor(None, inspector.ping)
        if replies:
            checks["celery_workers"] = "ok"
        else:
            # No workers answered — may be intentional (all idle / scaling
            # to zero). Treat as "degraded" rather than "error" so
            # the API stays routable for non-Celery endpoints.
            checks["celery_workers"] = "degraded"
            logger.warning("health/ready: no Celery workers responded to ping")
    except Exception as exc:
        logger.error("health/ready: celery check failed: %s", exc)
        checks["celery_workers"] = "error"

    all_ok = all(v == "ok" for v in checks.values())
    any_error = any(v == "error" for v in checks.values())

    if all_ok:
        overall = "ok"
    elif any_error:
        overall = "degraded"
        response.status_code = 503
    else:
        # Some "degraded" sub-checks but no hard errors — still serve.
        overall = "degraded"

    return {"status": overall, "checks": checks}
