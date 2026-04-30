# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
CSRF protection (double-submit cookie pattern).

Cookie-based sessions are vulnerable to CSRF because browsers attach
cookies to cross-origin requests automatically. We mitigate by issuing
a non-httpOnly `csrf_token` cookie at login and requiring the frontend
to echo it as the `X-CSRF-Token` header on state-changing requests.

Bearer / API-key authenticated requests are not vulnerable to CSRF
(no automatic credential attachment by the browser) and bypass this
check.
"""
import secrets

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}

# These endpoints either pre-date the session (login/register) or rotate
# it from a separate credential (refresh from the httpOnly refresh cookie).
EXEMPT_PATHS = {
    "/api/v1/auth/login",
    "/api/v1/auth/register",
    "/api/v1/auth/refresh",
    "/api/v1/auth/logout",
    # Forgot/reset (B05) run before the user has a session (the entire
    # flow exists because they CAN'T log in), so they have no csrf
    # cookie to double-submit. Exempting them is safe because:
    #  - forgot-password is rate-limited (5/min/IP) and always returns
    #    204 regardless of input, so CSRF + this endpoint can't be
    #    composed into an enumeration primitive either.
    #  - reset-password requires a single-use token delivered
    #    out-of-band by email; an attacker without read access to the
    #    user's inbox can't produce one.
    "/api/v1/auth/forgot-password",
    "/api/v1/auth/reset-password",
}


class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method in SAFE_METHODS:
            return await call_next(request)
        if request.url.path in EXEMPT_PATHS:
            return await call_next(request)
        # No cookie session => Bearer / API key flow => no CSRF risk.
        if not request.cookies.get("access_token"):
            return await call_next(request)

        cookie_csrf = request.cookies.get("csrf_token")
        header_csrf = request.headers.get("X-CSRF-Token")
        if (
            not cookie_csrf
            or not header_csrf
            or not secrets.compare_digest(cookie_csrf, header_csrf)
        ):
            return JSONResponse(
                {"detail": "CSRF token missing or invalid"},
                status_code=403,
            )
        return await call_next(request)
