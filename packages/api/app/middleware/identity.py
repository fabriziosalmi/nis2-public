# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Identity middleware.

Decodes the JWT once at request entry and exposes (user_id, org_id) to
downstream code via contextvars. This is the single source of identity
for:

  - AuditMiddleware (which logs every successful state-changing request);
  - the get_db dependency (which scopes Postgres RLS via
    `SET LOCAL app.current_org_id = ...`).

Anonymous requests (no token, expired token, malformed token) leave
both contextvars at their default of None — and that is the safe
default: an unset `app.current_org_id` makes every RLS policy
non-matching, so even a forgotten WHERE clause returns zero rows.
"""

from __future__ import annotations

import uuid
from contextvars import ContextVar
from typing import Optional

from fastapi import Request
from jwt import InvalidTokenError as JWTError
from starlette.middleware.base import BaseHTTPMiddleware

from app.utils.jwt import decode_token

current_user_id: ContextVar[Optional[uuid.UUID]] = ContextVar(
    "current_user_id", default=None
)
current_org_id: ContextVar[Optional[uuid.UUID]] = ContextVar(
    "current_org_id", default=None
)

# One identifier per request, carried through the same mechanism as the identity
# above and injected into every log record by app.logging_config.
#
# There was none. Production runs four gunicorn workers writing to one stream and
# a Celery worker writing asynchronously to another, so relating the records of a
# single operation was possible only by timestamp and guesswork — and the
# machinery to fix it was already here, being used to carry identity into the
# audit table. A user reporting "it failed at 14:02" had nothing an operator
# could search for.
#
# Accepted from the caller when it looks like one, so a request traced through a
# reverse proxy or a client SDK keeps its identifier; generated otherwise.
request_id: ContextVar[Optional[str]] = ContextVar("request_id", default=None)

REQUEST_ID_HEADER = "X-Request-Id"
_MAX_INBOUND_REQUEST_ID = 128


def _maybe_uuid(value: Optional[str]) -> Optional[uuid.UUID]:
    if not value:
        return None
    try:
        return uuid.UUID(value)
    except (ValueError, TypeError):
        return None


def _resolve_request_id(request: Request) -> str:
    """Reuse the caller's identifier when it is safe to, otherwise mint one.

    Bounded and stripped of anything that is not printable ASCII: this value
    reaches log lines and a response header, so an unbounded or newline-bearing
    header would be a log-injection primitive rather than a diagnostic aid.
    """
    inbound = request.headers.get(REQUEST_ID_HEADER, "")[:_MAX_INBOUND_REQUEST_ID]
    cleaned = "".join(c for c in inbound if c.isalnum() or c in "-_.")
    return cleaned or uuid.uuid4().hex


def _extract_token(request: Request) -> Optional[str]:
    cookie_token = request.cookies.get("access_token")
    if cookie_token:
        return cookie_token
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return None


class IdentityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # P1-04 audit fix: save ContextVar tokens so we can reset them
        # in the finally block. Without this, a valid identity from
        # Request A can leak into Request B if B is anonymous and
        # lands on the same asyncio task context (BaseHTTPMiddleware
        # runs each request as a task, and uvicorn reuses the event
        # loop). The ContextVar.set() method returns a Token that
        # allows us to reliably restore the previous value.
        uid_token = current_user_id.set(None)
        oid_token = current_org_id.set(None)
        rid_token = request_id.set(_resolve_request_id(request))
        try:
            token = _extract_token(request)
            if token:
                try:
                    payload = decode_token(token)
                    if payload.get("type") == "access":
                        current_user_id.set(_maybe_uuid(payload.get("sub")))
                        current_org_id.set(_maybe_uuid(payload.get("org_id")))
                except JWTError:
                    # Invalid token: leave contextvars at None. Auth dependencies
                    # downstream will produce a proper 401.
                    pass
            response = await call_next(request)
            # Returned so a user reporting a problem can quote something an
            # operator can grep for.
            response.headers[REQUEST_ID_HEADER] = request_id.get() or ""
            return response
        finally:
            # Always restore to prevent cross-request identity leakage.
            current_user_id.reset(uid_token)
            current_org_id.reset(oid_token)
            request_id.reset(rid_token)
