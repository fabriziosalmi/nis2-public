import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

from nis2_checker.web import app, get_session, init_governance_data
from nis2_checker.models import GovernanceChecklist, Target, ScanHistory

# Setup in-memory DB for testing
@pytest.fixture(name="session")
def session_fixture():
    engine = create_engine(
        "sqlite://", 
        connect_args={"check_same_thread": False}, 
        poolclass=StaticPool
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        init_governance_data(session) # Populate checklist
        yield session

@pytest.fixture(name="client")
def client_fixture(session: Session):
    def get_session_override():
        return session

    app.dependency_overrides[get_session] = get_session_override
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()

def test_read_dashboard(client: TestClient):
    response = client.get("/")
    assert response.status_code == 200
    assert "NIS2 Enterprise Platform" in response.text

def test_governance_page_load(client: TestClient):
    response = client.get("/governance")
    assert response.status_code == 200
    assert "Governance Checklist" in response.text
    # Check if items are loaded (we know there are 30 items)
    assert "Critical Priorities" in response.text

def test_update_governance_item(client: TestClient, session: Session):
    # Get an item
    item = session.exec(select(GovernanceChecklist)).first()
    assert item is not None
    
    response = client.post(
        f"/governance/update/{item.id}",
        data={"status": "Done", "notes": "Test Note"}
    )
    assert response.status_code == 200
    
    # Verify DB update
    session.refresh(item)
    assert item.status == "Done"
    assert item.notes == "Test Note"

def test_api_compliance_status(client: TestClient):
    response = client.get("/api/v1/compliance/status")
    assert response.status_code == 200
    data = response.json()
    assert "compliance_score" in data
    assert "technical_score" in data
    assert "governance_items_total" in data

def test_trigger_scan_api(client: TestClient):
    # Mocking background tasks is tricky in integration tests without running them
    # But we can check if the endpoint accepts the request
    response = client.post("/api/v1/scan/trigger", data={"target": "https://example.com"})
    assert response.status_code == 200
    assert data["status"] == "queued"
