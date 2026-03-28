import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import assets, auth, findings, health, organizations, reports, scans, schedules

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
        version="0.1.0",
        lifespan=lifespan,
    )

    # CORS middleware
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Restrict in production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include routers
    application.include_router(auth.router, prefix="/api/v1")
    application.include_router(scans.router, prefix="/api/v1")
    application.include_router(findings.router, prefix="/api/v1")
    application.include_router(assets.router, prefix="/api/v1")
    application.include_router(organizations.router, prefix="/api/v1")
    application.include_router(health.router, prefix="/api/v1")
    application.include_router(reports.router, prefix="/api/v1")
    application.include_router(schedules.router, prefix="/api/v1")

    return application


app = create_app()
