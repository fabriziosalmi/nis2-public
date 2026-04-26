# Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.routers import acn, api_keys, assets, auth, bia, certificates, findings, governance, health, incidents, organizations, remediation, reports, scans, schedules, vendors
from app.mcp_server import router as mcp_router
from app.routers.auth import limiter

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("NIS2 Platform API started")
    yield
    logger.info("NIS2 Platform API shutting down")


def create_app() -> FastAPI:
    application = FastAPI(
        title="NIS2 Compliance Platform API",
        description="API for the NIS2 compliance scanning and reporting platform",
        version="2.3.3",
        lifespan=lifespan,
    )

    # Rate limiter
    application.state.limiter = limiter
    application.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # CORS middleware
    allowed_origins = os.environ.get(
        "CORS_ORIGINS", "http://localhost:8077,http://localhost:3000"
    ).split(",")

    application.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Branding headers
    class BrandingMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            response = await call_next(request)
            response.headers["X-NIS2-Platform"] = "v2.3.1"
            response.headers["X-NIS2-Contact"] = "fabrizio.salmi@gmail.com"
            return response

    application.add_middleware(BrandingMiddleware)

    # Include routers
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
    application.include_router(certificates.router, prefix="/api/v1")
    application.include_router(remediation.router, prefix="/api/v1")
    application.include_router(vendors.router, prefix="/api/v1")
    application.include_router(bia.router, prefix="/api/v1")
    application.include_router(acn.router, prefix="/api/v1")
    application.include_router(mcp_router, prefix="/api/v1")

    return application


app = create_app()
