# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config import settings
from app.database import ensure_schema, setup_row_level_security
from app.middleware.audit import AuditMiddleware
from app.middleware.csrf import CSRFMiddleware
from app.middleware.identity import IdentityMiddleware
from app.routers import acn, api_keys, assets, audit, auth, bia, certificates, findings, governance, health, incidents, organizations, remediation, reports, scans, schedules, vendors
from app.mcp_server import router as mcp_router
from app.routers.auth import limiter

logger = logging.getLogger(__name__)

# Keep in lockstep with packages/api/pyproject.toml `version`. The
# Round-2 audit caught this hardcoded literal lagging behind the
# pyproject by three patch releases (2.4.26 vs 2.5.0), which made the
# audit log claim a wrong release was running.
API_VERSION = "2.5.1"

# Defence in depth: applied unconditionally at the API.
# Caddy adds equivalent headers at the edge in production deployments.
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=(), payment=()",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("NIS2 Platform API %s started (env=%s)", API_VERSION, settings.environment)
    # Bootstrap missing tables/columns on a fresh DB and heal any
    # additive schema drift on existing volumes. See ensure_schema for
    # the debt note — this is a stopgap until alembic/versions/ is
    # populated with proper revisions.
    try:
        await ensure_schema()
    except Exception:
        logger.exception("ensure_schema failed — continuing; expect schema-drift errors")
    # Idempotent failsafe: ensure tenant isolation is enforced at the
    # database layer too, not only by per-router WHERE clauses. If a
    # router ever forgets to filter by organization_id, RLS still
    # returns zero rows.
    try:
        await setup_row_level_security()
    except Exception:
        logger.exception("RLS setup failed — continuing with app-level isolation only")
    yield
    logger.info("NIS2 Platform API shutting down")


def _resolve_cors_origins() -> list[str]:
    if settings.cors_origins.strip():
        return [origin.strip() for origin in settings.cors_origins.split(",") if origin.strip()]
    # In production, Settings._validate_runtime_config has already raised.
    # We only reach this branch in non-production environments.
    return ["http://localhost:3000", "http://localhost:8077"]


def create_app() -> FastAPI:
    application = FastAPI(
        title="NIS2 Compliance Platform API",
        description="API for the NIS2 compliance scanning and reporting platform",
        version=API_VERSION,
        lifespan=lifespan,
    )

    application.state.limiter = limiter
    application.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # Middleware order: the LAST add_middleware call is the OUTERMOST.
    # Request flow:  CORS → Identity → CSRF → Audit → SecurityHeaders → app
    # Response flow: app → SecurityHeaders → Audit → CSRF → Identity → CORS
    #
    # Identity sits outside Audit because Audit reads the contextvars it
    # populates. CSRF stays between Identity and Audit so 403s on missing
    # CSRF still produce an audit-log entry on retry success.
    application.add_middleware(SecurityHeadersMiddleware)
    application.add_middleware(AuditMiddleware)
    application.add_middleware(CSRFMiddleware)
    application.add_middleware(IdentityMiddleware)
    application.add_middleware(
        CORSMiddleware,
        allow_origins=_resolve_cors_origins(),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-CSRF-Token", "X-Organization-Id"],
    )

    application.include_router(auth.router, prefix="/api/v1")
    application.include_router(scans.router, prefix="/api/v1")
    application.include_router(findings.router, prefix="/api/v1")
    application.include_router(assets.router, prefix="/api/v1")
    application.include_router(organizations.router, prefix="/api/v1")
    application.include_router(health.router, prefix="/api/v1")
    application.include_router(reports.router, prefix="/api/v1")
    application.include_router(schedules.router, prefix="/api/v1")
    application.include_router(incidents.router, prefix="/api/v1")
    application.include_router(governance.router, prefix="/api/v1")
    application.include_router(api_keys.router, prefix="/api/v1")
    application.include_router(audit.router, prefix="/api/v1")
    application.include_router(certificates.router, prefix="/api/v1")
    application.include_router(remediation.router, prefix="/api/v1")
    application.include_router(vendors.router, prefix="/api/v1")
    application.include_router(bia.router, prefix="/api/v1")
    application.include_router(acn.router, prefix="/api/v1")
    application.include_router(mcp_router, prefix="/api/v1")

    return application


app = create_app()
