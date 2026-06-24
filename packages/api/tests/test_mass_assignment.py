# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public

import uuid
import pytest
from fastapi.testclient import TestClient

from app.database import get_db
from app.dependencies import get_current_user
from app.main import create_app


class FakeUser:
    def __init__(self):
        self.id = uuid.uuid4()
        self.email = "test@nis2.local"
        self.full_name = "Test User"
        self.locale = "en"
        self.avatar_url = "/avatar.png"
        self.is_active = True
        self.email_verified = False


async def _fake_db():
    class FakeDbSession:
        async def flush(self):
            pass
    yield FakeDbSession()


@pytest.fixture
def fake_user():
    return FakeUser()


@pytest.fixture
def app(fake_user):
    app = create_app()
    app.dependency_overrides[get_db] = _fake_db
    app.dependency_overrides[get_current_user] = lambda: fake_user
    return app


@pytest.fixture
def client(app):
    return TestClient(app, raise_server_exceptions=False)


def test_update_me_whitelisted_fields_only(client, fake_user):
    payload = {
        "full_name": "New Name",
        "locale": "it",
        "avatar_url": "/new_avatar.png"
    }
    resp = client.patch("/api/v1/auth/me", json=payload)
    assert resp.status_code == 200
    assert fake_user.full_name == "New Name"
    assert fake_user.locale == "it"
    assert fake_user.avatar_url == "/new_avatar.png"


def test_update_me_non_whitelisted_fields_ignored(client, fake_user, monkeypatch):
    from app.schemas.auth import UserUpdate
    
    original_dump = UserUpdate.model_dump
    
    def mock_dump(*args, **kwargs):
        data = original_dump(*args, **kwargs)
        # Inject non-whitelisted fields simulating a schema change
        data["email_verified"] = True
        data["is_active"] = False
        return data
        
    monkeypatch.setattr(UserUpdate, "model_dump", mock_dump)
    
    payload = {
        "full_name": "New Name"
    }
    resp = client.patch("/api/v1/auth/me", json=payload)
    assert resp.status_code == 200
    
    # Whitelist must prevent modifications to email_verified and is_active
    assert fake_user.full_name == "New Name"
    assert fake_user.email_verified is False
    assert fake_user.is_active is True


def test_slim_token_response(fake_user):
    from fastapi import Response
    from app.routers.auth import _build_token_response
    
    response = Response()
    org_id = uuid.uuid4()
    
    # 1. Test when slim=False (default behavior)
    res_normal = _build_token_response(
        response=response,
        user=fake_user,
        organization_id=org_id,
        role="admin",
        slim=False
    )
    assert res_normal.access_token is not None
    assert res_normal.refresh_token is not None
    assert res_normal.csrf_token is not None
    assert res_normal.org_id == str(org_id)
    
    # 2. Test when slim=True (slim behavior)
    res_slim = _build_token_response(
        response=response,
        user=fake_user,
        organization_id=org_id,
        role="admin",
        slim=True
    )
    assert res_slim.access_token is None
    assert res_slim.refresh_token is None
    assert res_slim.csrf_token is not None
    assert res_slim.org_id == str(org_id)

