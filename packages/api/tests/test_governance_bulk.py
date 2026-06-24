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
        self.memberships = [FakeMembership(role, org_id)]

# We use an ephemeral UUID to simulate a valid Org ID
TEST_ORG_ID = uuid.uuid4()

async def _fake_db():
    yield None

async def _fake_user_admin():
    return FakeUser(role="admin", org_id=TEST_ORG_ID)

async def _fake_user_viewer():
    return FakeUser(role="viewer", org_id=TEST_ORG_ID)

@pytest.fixture
def app():
    app = create_app()
    app.dependency_overrides[get_db] = _fake_db
    return app

@pytest.fixture
def client_admin(app):
    app.dependency_overrides[get_current_user] = _fake_user_admin
    return TestClient(app, raise_server_exceptions=False)

@pytest.fixture
def client_viewer(app):
    app.dependency_overrides[get_current_user] = _fake_user_viewer
    return TestClient(app, raise_server_exceptions=False)

def test_bulk_update_unauthenticated(app):
    # TestClient without dependency override for user will simulate anonymous/unauthenticated
    # since no valid token is provided in headers/cookies.
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.post("/api/v1/governance/bulk-update", json={"items": []})
    assert resp.status_code in (401, 403)

def test_bulk_update_viewer_forbidden(client_viewer):
    resp = client_viewer.post("/api/v1/governance/bulk-update", json={"items": []})
    # Viewer role is not allowed (only admin, auditor)
    assert resp.status_code == 403

def test_bulk_update_invalid_uuid(client_admin):
    payload = {
        "items": [
            {
                "id": "not-a-uuid",
                "status": "done"
            }
        ]
    }
    resp = client_admin.post("/api/v1/governance/bulk-update", json=payload)
    assert resp.status_code == 422
    assert "id" in resp.text

def test_bulk_update_invalid_status(client_admin):
    payload = {
        "items": [
            {
                "id": str(uuid.uuid4()),
                "status": "super_done"  # Invalid status value
            }
        ]
    }
    resp = client_admin.post("/api/v1/governance/bulk-update", json=payload)
    assert resp.status_code == 422
    assert "status" in resp.text

def test_bulk_update_too_many_items(client_admin):
    payload = {
        "items": [
            {"id": str(uuid.uuid4()), "status": "done"}
            for _ in range(101)  # Limit is 100
        ]
    }
    resp = client_admin.post("/api/v1/governance/bulk-update", json=payload)
    assert resp.status_code == 422
    assert "items" in resp.text

def test_bulk_update_string_too_long(client_admin):
    payload = {
        "items": [
            {
                "id": str(uuid.uuid4()),
                "status": "done",
                "assigned_to_name": "A" * 257  # limit is 256
            }
        ]
    }
    resp = client_admin.post("/api/v1/governance/bulk-update", json=payload)
    assert resp.status_code == 422
    assert "assigned_to_name" in resp.text

def test_bulk_update_missing_items_key(client_admin):
    payload = {"other_field": "value"}  # Missing required 'items' key
    resp = client_admin.post("/api/v1/governance/bulk-update", json=payload)
    assert resp.status_code == 422
    assert "items" in resp.text

def test_bulk_update_valid_passes_schema(client_admin):
    payload = {
        "items": [
            {
                "id": str(uuid.uuid4()),
                "status": "in_progress",
                "assigned_to_name": "John Doe",
                "evidence_notes": "Some progress"
            }
        ]
    }
    resp = client_admin.post("/api/v1/governance/bulk-update", json=payload)
    # The payload is valid. Since the database is mocked to yield None,
    # the endpoint will bypass Pydantic validation successfully, enter the controller,
    # and then fail with 500 when it attempts to call db.get() on None.
    # A 500 status code confirms the schema validation succeeded!
    assert resp.status_code == 500
