# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
JWKS endpoint — GET /.well-known/jwks.json

In RS256 mode this publishes the RSA public key so external verifiers
(API gateways, third-party services) can validate tokens without
contacting the auth server.

In HS256 mode the endpoint returns an empty keyset; HMAC secrets are
symmetric and must never be published.
"""

import base64
import logging

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.config import settings

logger = logging.getLogger(__name__)

router = APIRouter()


def _int_to_base64url(n: int) -> str:
    """Encode an integer as base64url (no padding) as required by JWK spec."""
    length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()


@router.get("/.well-known/jwks.json", include_in_schema=True, tags=["auth"])
async def jwks() -> JSONResponse:
    """Return the JSON Web Key Set for this platform.

    RS256 mode: publishes the RSA public key (n, e) so external parties
    can verify tokens issued by this platform.

    HS256 mode: returns an empty keyset — HMAC keys are symmetric and
    must not be published.
    """
    if settings.jwt_algorithm != "RS256" or not settings.jwt_public_key:
        # HS256 or RS256 misconfigured — return empty keyset
        return JSONResponse(
            content={"keys": []},
            headers={"Cache-Control": "no-store"},
        )

    try:
        public_key = load_pem_public_key(settings.jwt_public_key.encode())
        pub_numbers = public_key.public_numbers()  # type: ignore[union-attr]
    except Exception:
        logger.exception("Failed to parse JWT_PUBLIC_KEY for JWKS endpoint")
        return JSONResponse(
            content={"keys": []},
            headers={"Cache-Control": "no-store"},
            status_code=500,
        )

    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "n": _int_to_base64url(pub_numbers.n),
        "e": _int_to_base64url(pub_numbers.e),
    }

    return JSONResponse(
        content={"keys": [jwk]},
        headers={"Cache-Control": "public, max-age=3600"},
    )
