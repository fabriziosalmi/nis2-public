# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""Prometheus metrics.

The production compose has shipped a Prometheus container since 2.4.x, scraping
three jobs of which two pointed at `/metrics` endpoints that did not exist. So a
deployment came up with two-thirds of its monitoring targets permanently red,
which costs twice: there was no application telemetry at all, and a monitoring
system whose targets are always red trains whoever looks at it to stop looking.

Deliberately few metrics, chosen for what an operator would alert on rather than
for coverage:

  * request rate, errors and latency, by method, path template and status — the
    path TEMPLATE, not the path, so an id in the URL cannot explode cardinality;
  * database connection-pool utilisation, which is the leading indicator of the
    failure this deployment is closest to. Four gunicorn workers each hold their
    own pool, so saturation used to arrive with no warning at all: Postgres
    refuses the connection, readiness starts failing and Caddy stops routing.

Unauthenticated on purpose, and mounted outside /api/v1: Prometheus scrapes it
over the compose network by service name, and those names are not externally
resolvable. Anyone exposing the API directly to the internet should block
/metrics at the edge, which the deployment guide now says.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request, Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    multiprocess,
)
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

router = APIRouter(tags=["metrics"])

REQUESTS = Counter(
    "nis2_http_requests_total",
    "HTTP requests handled.",
    ["method", "endpoint", "status"],
)

LATENCY = Histogram(
    "nis2_http_request_duration_seconds",
    "HTTP request duration.",
    ["method", "endpoint"],
)

DB_POOL_IN_USE = Gauge(
    "nis2_db_pool_connections_in_use",
    "Connections checked out of this worker's SQLAlchemy pool.",
)

DB_POOL_CAPACITY = Gauge(
    "nis2_db_pool_capacity",
    "Configured ceiling for this worker's pool (pool_size + max_overflow).",
)


def _endpoint_label(request: Request) -> str:
    """The route template, never the concrete path.

    /api/v1/scans/{scan_id} rather than /api/v1/scans/9f3c...: one series per
    route instead of one per resource, which is the difference between a metric
    and an outage caused by a metric.
    """
    route = request.scope.get("route")
    return getattr(route, "path", None) or "unmatched"


class MetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        import time

        started = time.perf_counter()
        status = "500"
        try:
            response = await call_next(request)
            status = str(response.status_code)
            return response
        finally:
            endpoint = _endpoint_label(request)
            # Never let instrumentation fail a request.
            try:
                REQUESTS.labels(request.method, endpoint, status).inc()
                LATENCY.labels(request.method, endpoint).observe(
                    time.perf_counter() - started
                )
            except Exception:  # noqa: BLE001
                logger.debug("metrics update failed", exc_info=True)


def _refresh_pool_gauges() -> None:
    """Sample the pool at scrape time rather than tracking every checkout."""
    try:
        from app.config import settings
        from app.database import engine

        pool = engine.pool
        checked_out = getattr(pool, "checkedout", None)
        DB_POOL_IN_USE.set(checked_out() if callable(checked_out) else 0)
        DB_POOL_CAPACITY.set(settings.db_pool_size + settings.db_max_overflow)
    except Exception:  # noqa: BLE001
        # NullPool (the Celery worker) has no checkout count; not an error.
        logger.debug("pool gauges unavailable", exc_info=True)


@router.get("/metrics", include_in_schema=False)
async def metrics() -> Response:
    _refresh_pool_gauges()

    # gunicorn preforks, so each worker holds its own counters. With
    # PROMETHEUS_MULTIPROC_DIR set, the client aggregates them across workers;
    # without it a scrape returns whichever worker answered, which is misleading
    # for counters and fine for nothing.
    import os

    if os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry)
        payload = generate_latest(registry)
    else:
        payload = generate_latest()

    return Response(content=payload, media_type=CONTENT_TYPE_LATEST)
