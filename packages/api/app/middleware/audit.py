# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Audit logging.

Two entry points:

- `log_action()` is the explicit per-call helper (used when a route
  wants to record a richer payload, e.g. resource_id and details).

- `AuditMiddleware` is the catch-all: it logs every successful
  state-changing request to `audit_logs`, attaching user_id and
  org_id parsed from the JWT (cookie or Bearer). This guarantees that
  no state-changing endpoint is silently un-audited.
"""
import logging
import uuid
from typing import Any, Optional

from fastapi import Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.base import BaseHTTPMiddleware

from app.database import IS_POSTGRES, async_session_factory
from app.middleware.identity import current_org_id, current_user_id
from app.models.audit_log import AuditLog


logger = logging.getLogger(__name__)

LOG_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Login/register pre-date the session, refresh re-issues it. We don't
# log them here because they're high-volume and don't represent
# meaningful state changes for a NIS2 audit trail.
EXEMPT_PATHS = {
    "/api/v1/auth/login",
    "/api/v1/auth/register",
    "/api/v1/auth/refresh",
    "/api/v1/auth/logout",
}


async def log_action(
    db: AsyncSession,
    org_id: uuid.UUID,
    user_id: uuid.UUID | None,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    details: dict[str, Any] | None = None,
    request: Request | None = None,
) -> AuditLog:
    """Create an audit log entry from inside a route handler."""
    ip_address: str | None = None
    user_agent: str | None = None

    if request:
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            ip_address = forwarded_for.split(",")[0].strip()
        elif request.client:
            ip_address = request.client.host
        user_agent = request.headers.get("user-agent")

    audit_entry = AuditLog(
        organization_id=org_id,
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details or {},
        ip_address=ip_address,
        user_agent=user_agent[:512] if user_agent else None,
    )
    db.add(audit_entry)
    await db.flush()

    return audit_entry


def _extract_ip(request: Request) -> Optional[str]:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return None


def _resource_type(path: str) -> str:
    parts = [p for p in path.split("/") if p]
    # /api/v1/<resource>/...
    if len(parts) >= 3 and parts[0] == "api" and parts[1] == "v1":
        return parts[2][:50]
    return "unknown"


class AuditMiddleware(BaseHTTPMiddleware):
    """Auto-log every successful state-changing request."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        if request.method not in LOG_METHODS:
            return response
        if request.url.path in EXEMPT_PATHS:
            return response
        if not (200 <= response.status_code < 300):
            return response

        # Identity is set by IdentityMiddleware (which wraps us). Re-reading
        # contextvars here keeps audit.py and database.py in sync — both
        # consume the single decoded JWT.
        user_id = current_user_id.get()
        org_id = current_org_id.get()
        if org_id is None:
            # Anonymous request hit a state-changing endpoint and got 2xx.
            # That's surprising; log a warning but don't block.
            logger.warning(
                "audit: 2xx state-change without org_id at %s %s",
                request.method,
                request.url.path,
            )
            return response

        ip_address = _extract_ip(request)
        user_agent = (request.headers.get("user-agent") or "")[:512]

        try:
            async with async_session_factory() as session:
                # The audit middleware runs in its own session, separate from
                # the request's get_db() session. We must scope it to the
                # tenant ourselves so the RLS WITH CHECK on audit_logs
                # accepts the INSERT. `SET LOCAL` does not accept bind
                # parameters; `set_config(..., is_local=true)` does.
                if IS_POSTGRES:
                    await session.execute(
                        text("SELECT set_config('app.current_org_id', :v, true)"),
                        {"v": str(org_id)},
                    )
                session.add(
                    AuditLog(
                        organization_id=org_id,
                        user_id=user_id,
                        action=request.method.lower(),
                        resource_type=_resource_type(request.url.path),
                        resource_id=None,
                        details={
                            "path": request.url.path,
                            "method": request.method,
                            "status": response.status_code,
                        },
                        ip_address=ip_address,
                        user_agent=user_agent or None,
                    )
                )
                await session.commit()
        except Exception:  # never break a successful response on logging failure
            logger.exception("audit: failed to write audit log")

        return response
