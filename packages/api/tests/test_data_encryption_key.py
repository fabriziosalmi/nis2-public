# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
"""M1: the field-level TOTP encryption key must never fall back to a hardcoded
literal, and production must require strong key material regardless of the JWT
algorithm. Pure-logic — no DB / HTTP / event loop."""
import hashlib
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def _gen_keypair() -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv, pub


PRIVATE_PEM, PUBLIC_PEM = _gen_keypair()
STRONG = "x" * 40  # >= 32 chars, not a placeholder


# --- crypto: key derivation ------------------------------------------------


def test_totp_key_prefers_data_encryption_key():
    from app import config
    from app.utils.crypto import get_totp_encryption_key

    with patch.multiple(
        config.settings, data_encryption_key="dedicated-" + STRONG, jwt_secret="jwt-" + STRONG
    ):
        expected = hashlib.sha256(("dedicated-" + STRONG).encode()).digest()
        assert get_totp_encryption_key() == expected


def test_totp_key_falls_back_to_jwt_secret():
    """Backward compat: deployments without DATA_ENCRYPTION_KEY keep deriving
    from JWT_SECRET — same key, so stored secrets stay decryptable."""
    from app import config
    from app.utils.crypto import get_totp_encryption_key

    with patch.multiple(config.settings, data_encryption_key="", jwt_secret="jwt-" + STRONG):
        expected = hashlib.sha256(("jwt-" + STRONG).encode()).digest()
        assert get_totp_encryption_key() == expected


def test_totp_key_fails_closed_with_no_material():
    """No literal fallback: with neither key set, refuse rather than derive a
    key from a hardcoded value (the M1 vulnerability)."""
    from app import config
    from app.utils.crypto import get_totp_encryption_key

    with patch.multiple(config.settings, data_encryption_key="", jwt_secret=""):
        with pytest.raises(RuntimeError):
            get_totp_encryption_key()


# --- config validation -----------------------------------------------------


def test_hs256_prod_boots_without_data_key():
    """Existing HS256 deployments (strong JWT_SECRET, no DATA_ENCRYPTION_KEY)
    must still boot — the TOTP key falls back to JWT_SECRET."""
    from app.config import Settings

    s = Settings(
        environment="production",
        jwt_algorithm="HS256",
        jwt_secret=STRONG,
        data_encryption_key="",
        cors_origins="https://x.example.com",
    )
    assert s.jwt_secret == STRONG


def test_rs256_prod_requires_data_key():
    """The M1 vuln: RS256 (no JWT_SECRET) without DATA_ENCRYPTION_KEY must refuse
    to start instead of keying MFA off a hardcoded literal."""
    from app.config import Settings

    with pytest.raises(RuntimeError) as exc:
        Settings(
            environment="production",
            jwt_private_key=PRIVATE_PEM,
            jwt_public_key=PUBLIC_PEM,
            jwt_secret="",
            data_encryption_key="",
            cors_origins="https://x.example.com",
        )
    assert "DATA_ENCRYPTION_KEY" in str(exc.value)


def test_rs256_prod_boots_with_data_key():
    from app.config import Settings

    s = Settings(
        environment="production",
        jwt_private_key=PRIVATE_PEM,
        jwt_public_key=PUBLIC_PEM,
        jwt_secret="",
        data_encryption_key=STRONG,
        cors_origins="https://x.example.com",
    )
    assert s.jwt_algorithm == "RS256"
    assert s.data_encryption_key == STRONG


def test_rs256_prod_boots_with_strong_jwt_secret_fallback():
    """Backward compat: an RS256 deploy that set a strong JWT_SECRET (no
    DATA_ENCRYPTION_KEY) keeps booting — the fallback is secure, not a literal."""
    from app.config import Settings

    s = Settings(
        environment="production",
        jwt_private_key=PRIVATE_PEM,
        jwt_public_key=PUBLIC_PEM,
        jwt_secret=STRONG,
        data_encryption_key="",
        cors_origins="https://x.example.com",
    )
    assert s.jwt_algorithm == "RS256"
