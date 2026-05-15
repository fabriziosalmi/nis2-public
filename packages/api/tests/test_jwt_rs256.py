# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for RS256 JWT support with HS256 fallback (issue #87)."""
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt, JWTError
from unittest.mock import patch


def _gen_keypair() -> tuple[str, str]:
    """Generate an RSA keypair; returns (private_pem, public_pem)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


PRIVATE_PEM, PUBLIC_PEM = _gen_keypair()
PRIVATE_PEM2, PUBLIC_PEM2 = _gen_keypair()  # different keypair for mismatch tests


# ---------------------------------------------------------------------------
# Helpers — patch settings in-place
# ---------------------------------------------------------------------------

def _patch_hs256():
    """Return a context manager that forces HS256 config."""
    from app import config as _cfg
    return patch.multiple(
        _cfg.settings,
        jwt_algorithm="HS256",
        jwt_secret="a-sufficiently-long-hs256-secret-key-32",
        jwt_private_key="",
        jwt_public_key="",
    )


def _patch_rs256():
    """Return a context manager that forces RS256 config."""
    from app import config as _cfg
    return patch.multiple(
        _cfg.settings,
        jwt_algorithm="RS256",
        jwt_private_key=PRIVATE_PEM,
        jwt_public_key=PUBLIC_PEM,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_hs256_round_trip():
    """HS256 encode/decode round-trip produces identical payload."""
    with _patch_hs256():
        from app.utils import jwt as jwt_util
        import importlib; importlib.reload(jwt_util)

        token = jwt_util.create_access_token({"sub": "user-1"})
        payload = jwt_util.decode_token(token)
        assert payload["sub"] == "user-1"
        assert payload["type"] == "access"


def test_rs256_round_trip():
    """RS256 encode/decode round-trip with generated keypair."""
    with _patch_rs256():
        from app.utils import jwt as jwt_util
        import importlib; importlib.reload(jwt_util)

        token = jwt_util.create_access_token({"sub": "user-rs256"})
        payload = jwt_util.decode_token(token)
        assert payload["sub"] == "user-rs256"
        assert payload["type"] == "access"

        # Verify algorithm header in the token
        header = jwt.get_unverified_header(token)
        assert header["alg"] == "RS256"


def test_rs256_token_rejected_with_wrong_public_key():
    """RS256 token signed with key-1 must be rejected when verifying with key-2."""
    with _patch_rs256():
        from app.utils import jwt as jwt_util
        import importlib; importlib.reload(jwt_util)

        token = jwt_util.create_access_token({"sub": "user-rs256"})

    # Now verify with a *different* public key
    from app import config as _cfg
    with patch.multiple(
        _cfg.settings,
        jwt_algorithm="RS256",
        jwt_private_key=PRIVATE_PEM2,
        jwt_public_key=PUBLIC_PEM2,
    ):
        import importlib; importlib.reload(jwt_util)
        with pytest.raises(JWTError):
            jwt_util.decode_token(token)


def test_hs256_token_rejected_by_rs256_decoder():
    """An HS256 token must be rejected when the decoder expects RS256."""
    with _patch_hs256():
        from app.utils import jwt as jwt_util
        import importlib; importlib.reload(jwt_util)
        hs_token = jwt_util.create_access_token({"sub": "user-hs"})

    # Try to verify the HS256 token as RS256 — must fail
    with _patch_rs256():
        import importlib; importlib.reload(jwt_util)
        with pytest.raises(JWTError):
            jwt_util.decode_token(hs_token)


def test_signing_key_returns_private_key_for_rs256():
    """_signing_key() must return the RSA private key in RS256 mode."""
    with _patch_rs256():
        from app.utils import jwt as jwt_util
        import importlib; importlib.reload(jwt_util)
        assert jwt_util._signing_key() == PRIVATE_PEM


def test_verifying_key_returns_public_key_for_rs256():
    """_verifying_key() must return the RSA public key in RS256 mode."""
    with _patch_rs256():
        from app.utils import jwt as jwt_util
        import importlib; importlib.reload(jwt_util)
        assert jwt_util._verifying_key() == PUBLIC_PEM


def test_signing_key_returns_secret_for_hs256():
    """_signing_key() must return jwt_secret in HS256 mode."""
    with _patch_hs256():
        from app.utils import jwt as jwt_util
        import importlib; importlib.reload(jwt_util)
        from app.config import settings
        assert jwt_util._signing_key() == settings.jwt_secret


def test_verifying_key_returns_secret_for_hs256():
    """_verifying_key() must return jwt_secret in HS256 mode."""
    with _patch_hs256():
        from app.utils import jwt as jwt_util
        import importlib; importlib.reload(jwt_util)
        from app.config import settings
        assert jwt_util._verifying_key() == settings.jwt_secret


def test_settings_algorithm_forced_to_rs256_when_private_key_set():
    """Settings must set jwt_algorithm=RS256 when jwt_private_key is non-empty."""
    from app.config import Settings

    s = Settings(
        environment="development",
        jwt_private_key=PRIVATE_PEM,
        jwt_public_key=PUBLIC_PEM,
        jwt_secret="some-secret-that-is-at-least-32-chars-long",
        cors_origins="http://localhost:3000",
    )
    assert s.jwt_algorithm == "RS256"


def test_settings_hs256_unchanged_when_no_private_key():
    """Settings must keep jwt_algorithm=HS256 when jwt_private_key is empty."""
    from app.config import Settings

    s = Settings(
        environment="development",
        jwt_private_key="",
        jwt_secret="some-secret-that-is-at-least-32-chars-long",
        cors_origins="http://localhost:3000",
    )
    assert s.jwt_algorithm == "HS256"


def test_rs256_refresh_token_round_trip():
    """RS256 refresh tokens also encode/decode correctly."""
    with _patch_rs256():
        from app.utils import jwt as jwt_util
        import importlib; importlib.reload(jwt_util)

        token = jwt_util.create_refresh_token({"sub": "user-refresh"})
        payload = jwt_util.decode_token(token)
        assert payload["sub"] == "user-refresh"
        assert payload["type"] == "refresh"
