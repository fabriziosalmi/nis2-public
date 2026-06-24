# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public

import uuid
import pytest
import hashlib
from fastapi.testclient import TestClient
from passlib.context import CryptContext

from app.database import get_db
from app.dependencies import get_current_user
from app.main import create_app

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class FakeUser:
    def __init__(self):
        self.id = uuid.uuid4()
        self.email = "test@nis2.com"
        self.full_name = "Test User"
        self.locale = "en"
        self.avatar_url = "/avatar.png"
        self.is_active = True
        self.email_verified = False
        self.password_hash = pwd_context.hash("securepassword")
        self.totp_enabled = False
        self.totp_secret = "JBSWY3DPEHPK3PXP"
        self.totp_recovery_codes = None
        self.memberships = []


class FakeMembership:
    def __init__(self, user_id):
        self.id = uuid.uuid4()
        self.user_id = user_id
        self.organization_id = uuid.uuid4()
        self.role = "admin"


@pytest.fixture
def fake_user():
    return FakeUser()


@pytest.fixture
def fake_membership(fake_user):
    return FakeMembership(fake_user.id)


@pytest.fixture
def app(fake_user, fake_membership):
    app = create_app()

    class FakeDbSession:
        def __init__(self, user, membership):
            self.user = user
            self.membership = membership

        async def execute(self, query, *args, **kwargs):
            class FakeResult:
                def __init__(self, val):
                     self.val = val
                def scalar_one_or_none(self):
                     return self.val
                def scalars(self):
                     class FakeScalars:
                         def __init__(self, val):
                             self.val = val
                         def first(self):
                             return self.val
                     return FakeScalars(self.val)
            query_str = str(query)
            if "membership" in query_str.lower():
                return FakeResult(self.membership)
            return FakeResult(self.user)

        async def flush(self):
            pass

    async def _fake_db():
        yield FakeDbSession(fake_user, fake_membership)

    app.dependency_overrides[get_db] = _fake_db
    app.dependency_overrides[get_current_user] = lambda: fake_user
    return app


@pytest.fixture
def client(app):
    return TestClient(app, raise_server_exceptions=True)


def test_totp_setup_and_verify_generates_recovery_codes(client, fake_user):
    # Setup TOTP
    resp_setup = client.post("/api/v1/auth/totp/setup")
    assert resp_setup.status_code == 200
    
    # Verify TOTP code with standard pyotp to enable MFA
    import pyotp
    totp = pyotp.TOTP(fake_user.totp_secret)
    code = totp.now()
    
    resp_verify = client.post("/api/v1/auth/totp/verify", json={"code": code})
    assert resp_verify.status_code == 200
    data = resp_verify.json()
    assert data["mfa_enabled"] is True
    
    # Check that recovery codes are generated and returned
    recovery_codes = data["recovery_codes"]
    assert len(recovery_codes) == 8
    for code in recovery_codes:
        assert len(code) == 14  # xxxx-xxxx-xxxx format
        assert code.count("-") == 2

    # Check that the hashes are stored in the database
    assert fake_user.totp_recovery_codes is not None
    stored_hashes = fake_user.totp_recovery_codes.split(",")
    assert len(stored_hashes) == 8
    
    # Verify the SHA-256 match
    for raw_code, stored_hash in zip(recovery_codes, stored_hashes):
        assert hashlib.sha256(raw_code.encode()).hexdigest() == stored_hash


def test_login_with_recovery_code(client, fake_user):
    # Prepare user with active MFA and recovery codes
    fake_user.totp_enabled = True
    raw_codes = ["abcd-1234-ef56", "1234-abcd-56ef"]
    fake_user.totp_recovery_codes = ",".join(
        hashlib.sha256(c.encode()).hexdigest() for c in raw_codes
    )

    # 1. Login with password only (partial login, MFA required)
    resp = client.post("/api/v1/auth/login", json={
        "email": fake_user.email,
        "password": "securepassword"
    })
    assert resp.status_code == 200
    assert resp.json().get("mfa_required") is True

    # 2. Login with valid recovery code
    resp_rc = client.post("/api/v1/auth/login", json={
        "email": fake_user.email,
        "password": "securepassword",
        "totp_code": "abcd-1234-ef56"
    })
    assert resp_rc.status_code == 200
    assert "access_token" in resp_rc.json() or "csrf_token" in resp_rc.json()

    # Verify recovery code has been consumed (removed from the DB list)
    remaining_hashes = fake_user.totp_recovery_codes.split(",")
    assert len(remaining_hashes) == 1
    assert hashlib.sha256(b"abcd-1234-ef56").hexdigest() not in remaining_hashes
    assert remaining_hashes[0] == hashlib.sha256(b"1234-abcd-56ef").hexdigest()

    # 3. Try logging in again with the same (now consumed) recovery code -> should fail
    resp_retry = client.post("/api/v1/auth/login", json={
        "email": fake_user.email,
        "password": "securepassword",
        "totp_code": "abcd-1234-ef56"
    })
    assert resp_retry.status_code == 401
    assert "invalid" in resp_retry.json().get("detail", "").lower()


def test_totp_disable_clears_recovery_codes(client, fake_user):
    fake_user.totp_enabled = True
    fake_user.totp_recovery_codes = "some_hashes_here"

    # Disable TOTP requires current password and new_password (schema requirement)
    resp = client.post("/api/v1/auth/totp/disable", json={
        "current_password": "securepassword",
        "new_password": "newsecurepassword"
    })
    assert resp.status_code == 200
    assert resp.json()["mfa_enabled"] is False
    assert fake_user.totp_enabled is False
    assert fake_user.totp_recovery_codes is None
