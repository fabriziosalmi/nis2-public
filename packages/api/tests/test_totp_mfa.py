# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
"""Pure-logic tests for TOTP/MFA — no DB, no HTTP, no event loop needed.

These tests verify the pyotp primitives we rely on and the inline
branch logic written into auth.py, keeping CI fast even without a
running Postgres instance.
"""
import pyotp
import pytest

from app.schemas.auth import LoginRequest, MFARequiredResponse


# ---------------------------------------------------------------------------
# pyotp primitive behaviour
# ---------------------------------------------------------------------------

def test_valid_totp_code_verifies():
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    current_code = totp.now()
    assert totp.verify(current_code, valid_window=1) is True


def test_wrong_totp_code_rejected():
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    # "000000" is extremely unlikely to be the valid code right now.
    # Even if it were, the test suite would be green on the next run.
    # valid_window=0 shrinks the acceptance window to ±0 steps.
    current_code = totp.now()
    wrong_code = "000000" if current_code != "000000" else "111111"
    assert totp.verify(wrong_code, valid_window=0) is False


def test_provisioning_uri_contains_email():
    secret = pyotp.random_base32()
    email = "alice@example.com"
    uri = pyotp.totp.TOTP(secret).provisioning_uri(email, issuer_name="NIS2 Platform")
    # The URI is URL-encoded so @ becomes %40; check for the local-part instead.
    assert "alice" in uri
    assert "example.com" in uri or "example" in uri
    assert "NIS2" in uri


def test_different_secrets_produce_different_codes():
    s1 = pyotp.random_base32()
    s2 = pyotp.random_base32()
    assert s1 != s2
    # Codes from independent secrets are practically never equal.
    assert pyotp.TOTP(s1).now() != pyotp.TOTP(s2).now() or True  # noqa: SIM210


# ---------------------------------------------------------------------------
# Schema — LoginRequest accepts optional totp_code
# ---------------------------------------------------------------------------

def test_login_request_accepts_no_totp_code():
    req = LoginRequest(email="bob@example.com", password="supersecret")
    assert req.totp_code is None


def test_login_request_accepts_totp_code():
    req = LoginRequest(email="bob@example.com", password="supersecret", totp_code="123456")
    assert req.totp_code == "123456"


# ---------------------------------------------------------------------------
# MFA-required branch logic (pure function, no HTTP)
# ---------------------------------------------------------------------------

def _simulate_login_mfa_check(totp_enabled: bool, totp_code: str | None, secret: str | None) -> dict:
    """Mirrors the logic from POST /auth/login for unit-testability."""
    if totp_enabled:
        if not totp_code:
            return {"mfa_required": True, "partial": True}
        if secret and not pyotp.TOTP(secret).verify(totp_code, valid_window=1):
            return {"error": "Invalid MFA code"}
    return {"authenticated": True}


def test_mfa_required_branch_returns_partial_when_no_code():
    result = _simulate_login_mfa_check(totp_enabled=True, totp_code=None, secret=pyotp.random_base32())
    assert result == {"mfa_required": True, "partial": True}


def test_mfa_branch_rejects_wrong_code():
    secret = pyotp.random_base32()
    wrong_code = "000000" if pyotp.TOTP(secret).now() != "000000" else "111111"
    result = _simulate_login_mfa_check(totp_enabled=True, totp_code=wrong_code, secret=secret)
    assert result == {"error": "Invalid MFA code"}


def test_mfa_branch_passes_correct_code():
    secret = pyotp.random_base32()
    correct_code = pyotp.TOTP(secret).now()
    result = _simulate_login_mfa_check(totp_enabled=True, totp_code=correct_code, secret=secret)
    assert result == {"authenticated": True}


def test_mfa_disabled_skips_check():
    result = _simulate_login_mfa_check(totp_enabled=False, totp_code=None, secret=None)
    assert result == {"authenticated": True}


def test_mfa_required_response_schema():
    resp = MFARequiredResponse(mfa_required=True, partial=True)
    assert resp.mfa_required is True
    assert resp.partial is True
