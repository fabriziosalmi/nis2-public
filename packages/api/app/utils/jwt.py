# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import uuid
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt

from app.config import settings


def _new_jti() -> str:
    return str(uuid.uuid4())


def _signing_key() -> str:
    """Return the key used to sign tokens.

    RS256 mode: the PEM-encoded RSA private key.
    HS256 mode: the shared HMAC secret.
    """
    if settings.jwt_algorithm == "RS256":
        return settings.jwt_private_key
    return settings.jwt_secret


def _verifying_key() -> str:
    """Return the key used to verify tokens.

    RS256 mode: the PEM-encoded RSA public key.
    HS256 mode: the shared HMAC secret.
    """
    if settings.jwt_algorithm == "RS256":
        return settings.jwt_public_key
    return settings.jwt_secret


def create_access_token(data: dict, iat_override: datetime | None = None) -> str:
    to_encode = data.copy()
    now = iat_override or datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.access_token_expire_minutes)
    # `iat` is needed by the password-change session-invalidation check
    # in dependencies / /refresh: any token with iat < user.password_changed_at
    # is rejected even before its `exp` would expire it. Without iat, the
    # only invalidation knob is exp, which means a 30-min window where the
    # old password's tokens stay valid even after a forced reset.
    #
    # `iat_override` lets /change-password align the new token's iat with
    # the password_changed_at watermark to the second, so already-issued
    # tokens minted in the same wall-clock second are guaranteed to be
    # rejected while the just-issued tokens are guaranteed to pass.
    to_encode.update({"iat": now, "exp": expire, "type": "access", "jti": _new_jti()})
    return jwt.encode(to_encode, _signing_key(), algorithm=settings.jwt_algorithm)


def create_refresh_token(data: dict, iat_override: datetime | None = None) -> str:
    to_encode = data.copy()
    now = iat_override or datetime.now(timezone.utc)
    expire = now + timedelta(days=settings.refresh_token_expire_days)
    to_encode.update({"iat": now, "exp": expire, "type": "refresh", "jti": _new_jti()})
    return jwt.encode(to_encode, _signing_key(), algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token. Raises JWTError on invalid tokens."""
    try:
        payload = jwt.decode(
            token, _verifying_key(), algorithms=[settings.jwt_algorithm]
        )
        return payload
    except JWTError:
        raise
