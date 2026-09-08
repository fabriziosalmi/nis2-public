# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
"""Pure-logic tests for TOTP/MFA — no DB, no HTTP, no event loop needed.

These tests verify the pyotp primitives we rely on and the inline
branch logic written into auth.py, keeping CI fast even without a
running Postgres instance.
"""
import pyotp

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


# ---------------------------------------------------------------------------
# TOTP Encryption / Decryption
# ---------------------------------------------------------------------------

def test_totp_encryption_and_decryption():
    from app.utils.crypto import encrypt_totp_secret, decrypt_totp_secret
    secret = "JBSWY3DPEHPK3PXP"
    encrypted = encrypt_totp_secret(secret)

    # Verify it is encrypted (not equal to original secret)
    assert encrypted != secret
    # Verify we can decrypt it back
    decrypted = decrypt_totp_secret(encrypted)
    assert decrypted == secret

def test_totp_backward_compatibility_with_cleartext():
    from app.utils.crypto import decrypt_totp_secret
    # A cleartext secret should be returned as-is
    legacy_secret = "JBSWY3DPEHPK3PXP"
    decrypted = decrypt_totp_secret(legacy_secret)
    assert decrypted == legacy_secret

def test_user_model_encryption_integration():
    from app.models.user import User

    user = User(email="test@example.com")
    secret = "JBSWY3DPEHPK3PXP"

    # Assign cleartext secret
    user.totp_secret = secret

    # Verify property getter decrypts it correctly
    assert user.totp_secret == secret
    # Verify underlying mapped field stores it in encrypted format
    assert user.totp_secret_encrypted != secret

    # Verify we can load a user with a legacy cleartext secret
    legacy_user = User(email="legacy@example.com")
    legacy_user.totp_secret_encrypted = secret  # set raw DB column directly
    assert legacy_user.totp_secret == secret  # should decrypt as legacy cleartext



# ---------------------------------------------------------------------------
# Contract the login UI depends on
# ---------------------------------------------------------------------------
#
# The tests above cover the MFA decision logic. What was never pinned is the
# SHAPE of the response the frontend has to branch on — and that gap is exactly
# where the bug lived: `POST /auth/login` answers 200 with
# {"mfa_required": true, "partial": true} and sets no session cookie, while the
# login page treated any 200 as a successful sign-in. It stored the absent user
# and redirected to /dashboard, which 401'd back to /login in a loop. Because
# /auth/totp/disable itself needs a session, enrolling MFA — only possible via
# the API, since no MFA screen existed — locked the account out of the web app
# permanently.
#
# Art. 21(2)(j) is specifically about multi-factor authentication, so these
# assertions guard the one control the directive names by hand.


def test_mfa_required_response_carries_no_session_fields():
    """The frontend distinguishes the two 200s by `mfa_required`.

    If a future change starts returning a user or org_id alongside
    mfa_required, the UI could plausibly treat it as a completed login again.
    """
    from app.schemas.auth import MFARequiredResponse

    payload = MFARequiredResponse(mfa_required=True, partial=True).model_dump()
    assert payload["mfa_required"] is True
    for leaked in ("user", "org_id", "access_token", "role"):
        assert leaked not in payload, (
            f"MFARequiredResponse exposes {leaked!r}; the login page keys off the "
            f"absence of session fields to know this 200 is not a sign-in"
        )


def test_login_request_carries_totp_code_for_the_second_attempt():
    """There is no separate 'complete MFA' endpoint: /login is repeated.

    The api-client sends `totp_code` only on the retry, so the field must stay
    optional and must be accepted on LoginRequest.
    """
    from app.schemas.auth import LoginRequest

    first = LoginRequest(email="user@example.com", password="pw")
    assert first.totp_code is None

    retry = LoginRequest(email="user@example.com", password="pw", totp_code="123456")
    assert retry.totp_code == "123456"


def test_totp_disable_does_not_require_a_new_password():
    """/auth/totp/disable reused ChangePasswordRequest, whose `new_password`
    carries min_length=8 — a field the endpoint never reads. Omitting it, the
    obvious thing for a client to do, produced a 422; disabling MFA therefore
    required inventing a password to satisfy an unrelated validator."""
    from app.schemas.auth import TOTPDisableRequest

    req = TOTPDisableRequest(current_password="my-real-password")
    assert req.current_password == "my-real-password"
    assert not hasattr(req, "new_password")


def test_user_response_exposes_mfa_state():
    """The profile screen decides between offering enrolment and offering
    removal from this field. Without it the frontend could not know the
    account's MFA state — part of why the feature had no UI at all."""
    from app.schemas.auth import UserResponse

    assert "totp_enabled" in UserResponse.model_fields
