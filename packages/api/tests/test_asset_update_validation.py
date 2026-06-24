import uuid
import pytest
from fastapi.testclient import TestClient

from app.database import get_db
from app.dependencies import get_current_user
from app.main import create_app

class FakeMembership:
    def __init__(self, role, org_id):
        self.role = role
        self.organization_id = org_id

class FakeUser:
    def __init__(self, role, org_id):
        self.id = uuid.uuid4()
        self.memberships = [FakeMembership(role, org_id)]

TEST_ORG_ID = uuid.uuid4()
TEST_ASSET_ID = uuid.uuid4()

class FakeAsset:
    def __init__(self):
        from datetime import datetime
        self.id = TEST_ASSET_ID
        self.organization_id = TEST_ORG_ID
        self.name = "Test Asset"
        self.target_type = "domain"
        self.target_value = "example.com"
        self.pinned_ip = "93.184.216.34"
        self.is_active = True
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()

class FakeResult:
    def scalar_one_or_none(self):
        return None

class FakeDbSession:
    async def get(self, model_class, ident):
        if ident == TEST_ASSET_ID:
            return FakeAsset()
        return None

    async def execute(self, statement):
        return FakeResult()

    def add(self, instance):
        pass

    async def flush(self):
        pass

async def _fake_db():
    yield FakeDbSession()

async def _fake_user_admin():
    return FakeUser(role="admin", org_id=TEST_ORG_ID)

@pytest.fixture
def app():
    app = create_app()
    app.dependency_overrides[get_db] = _fake_db
    app.dependency_overrides[get_current_user] = _fake_user_admin
    return app

@pytest.fixture
def client(app):
    return TestClient(app, raise_server_exceptions=False)

def test_update_asset_with_invalid_target_domain(client):
    payload = {
        "target_type": "domain",
        "target_value": "localhost"
    }
    resp = client.patch(f"/api/v1/assets/{TEST_ASSET_ID}", json=payload)
    assert resp.status_code == 422
    assert "Blocked hostname" in resp.text

def test_update_asset_with_invalid_target_ip(client):
    payload = {
        "target_type": "ip",
        "target_value": "127.0.0.1"
    }
    resp = client.patch(f"/api/v1/assets/{TEST_ASSET_ID}", json=payload)
    assert resp.status_code == 422

def test_update_asset_with_valid_target_passes_validation(client):
    payload = {
        "target_type": "domain",
        "target_value": "google.com"
    }
    resp = client.patch(f"/api/v1/assets/{TEST_ASSET_ID}", json=payload)
    # The valid update passes validation, finishes processing, writes to log, and returns 200 OK!
    assert resp.status_code == 200
    data = resp.json()
    assert data["target_value"] == "google.com"
    assert data["target_type"] == "domain"
    # It must have successfully pinned the IP (non-empty string)
    assert data["pinned_ip"] is not None
