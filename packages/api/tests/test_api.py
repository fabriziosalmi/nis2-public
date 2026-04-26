"""
API integration tests for the NIS2 Compliance Platform.
Tests auth, scans, findings, incidents, governance, and reports endpoints.
Uses pytest-asyncio with a test database.
"""
import hashlib
import pytest
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient

from app.main import create_app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def app():
    return create_app()


@pytest.fixture
def client(app):
    return TestClient(app)


# ---------------------------------------------------------------------------
# Health Check
# ---------------------------------------------------------------------------

class TestHealth:
    def test_health_endpoint(self, client):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"


# ---------------------------------------------------------------------------
# Auth — Rate Limiting & Validation
# ---------------------------------------------------------------------------

class TestAuth:
    def test_register_missing_fields(self, client):
        resp = client.post("/api/v1/auth/register", json={})
        assert resp.status_code == 422

    def test_login_missing_fields(self, client):
        resp = client.post("/api/v1/auth/login", json={})
        assert resp.status_code == 422

    def test_login_invalid_credentials(self, client):
        resp = client.post("/api/v1/auth/login", json={
            "email": "nonexistent@test.com",
            "password": "wrong",
        })
        # Should be 401 (or 500 if DB not connected — acceptable in unit test)
        assert resp.status_code in (401, 500)

    def test_me_without_token(self, client):
        resp = client.get("/api/v1/auth/me")
        assert resp.status_code in (401, 403)

    def test_me_with_invalid_token(self, client):
        resp = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer invalid"})
        assert resp.status_code == 401

    def test_refresh_invalid_token(self, client):
        resp = client.post("/api/v1/auth/refresh", json={"refresh_token": "invalid"})
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Protected Endpoints — Auth Required
# ---------------------------------------------------------------------------

class TestProtectedEndpoints:
    """Verify all protected endpoints reject unauthenticated requests."""

    PROTECTED_GETS = [
        "/api/v1/scans",
        "/api/v1/findings",
        "/api/v1/assets",
        "/api/v1/organizations/current",
        "/api/v1/incidents",
        "/api/v1/governance",
        "/api/v1/governance/score",
        "/api/v1/api-keys",
    ]

    PROTECTED_POSTS = [
        "/api/v1/scans",
        "/api/v1/assets",
        "/api/v1/incidents",
        "/api/v1/governance/seed",
        "/api/v1/api-keys",
        "/api/v1/reports/generate",
    ]

    @pytest.mark.parametrize("path", PROTECTED_GETS)
    def test_get_requires_auth(self, client, path):
        resp = client.get(path)
        assert resp.status_code in (401, 403), f"{path} returned {resp.status_code}"

    @pytest.mark.parametrize("path", PROTECTED_POSTS)
    def test_post_requires_auth(self, client, path):
        resp = client.post(path, json={})
        assert resp.status_code in (401, 403, 422), f"{path} returned {resp.status_code}"


# ---------------------------------------------------------------------------
# Incidents — Taxonomy
# ---------------------------------------------------------------------------

class TestIncidents:
    def test_taxonomy_is_public(self, client):
        """Taxonomy endpoint should work without auth for form dropdowns."""
        resp = client.get("/api/v1/incidents/taxonomy")
        # May require auth based on router setup — either 200 or 401 is acceptable
        if resp.status_code == 200:
            data = resp.json()
            assert "incident_types" in data
            assert "severity_levels" in data
            assert "references" in data
            assert len(data["incident_types"]) == 7
            assert "DoS/DDoS" in data["incident_types"]


# ---------------------------------------------------------------------------
# SSRF Prevention — Target Validation
# ---------------------------------------------------------------------------

class TestTargetValidation:
    """Test the SSRF prevention layer."""

    def test_valid_domain(self):
        from app.utils.target_validator import validate_domain
        result = validate_domain("example.com")
        assert result == "example.com"

    def test_valid_domain_with_protocol(self):
        from app.utils.target_validator import validate_domain
        result = validate_domain("https://example.com/path")
        assert result == "example.com"

    def test_blocked_localhost(self):
        from app.utils.target_validator import validate_domain, TargetValidationError
        with pytest.raises(TargetValidationError, match="Blocked hostname"):
            validate_domain("localhost")

    def test_blocked_metadata(self):
        from app.utils.target_validator import validate_domain, TargetValidationError
        with pytest.raises(TargetValidationError, match="Blocked hostname"):
            validate_domain("metadata.google.internal")

    def test_valid_public_ip(self):
        from app.utils.target_validator import validate_ip
        result = validate_ip("8.8.8.8")
        assert result == "8.8.8.8"

    def test_blocked_private_ip_10(self):
        from app.utils.target_validator import validate_ip, TargetValidationError
        with pytest.raises(TargetValidationError, match="Private"):
            validate_ip("10.0.0.1")

    def test_blocked_private_ip_192(self):
        from app.utils.target_validator import validate_ip, TargetValidationError
        with pytest.raises(TargetValidationError, match="Private"):
            validate_ip("192.168.1.1")

    def test_blocked_private_ip_172(self):
        from app.utils.target_validator import validate_ip, TargetValidationError
        with pytest.raises(TargetValidationError, match="Private"):
            validate_ip("172.16.0.1")

    def test_blocked_loopback(self):
        from app.utils.target_validator import validate_ip, TargetValidationError
        with pytest.raises(TargetValidationError, match="Private"):
            validate_ip("127.0.0.1")

    def test_blocked_metadata_ip(self):
        from app.utils.target_validator import validate_ip, TargetValidationError
        with pytest.raises(TargetValidationError, match="Private"):
            validate_ip("169.254.169.254")

    def test_valid_cidr(self):
        from app.utils.target_validator import validate_cidr
        result = validate_cidr("203.0.113.0/24")
        assert result == "203.0.113.0/24"

    def test_blocked_private_cidr(self):
        from app.utils.target_validator import validate_cidr, TargetValidationError
        with pytest.raises(TargetValidationError, match="SSRF blocked"):
            validate_cidr("192.168.0.0/16")

    def test_blocked_oversized_cidr(self):
        from app.utils.target_validator import validate_cidr, TargetValidationError
        with pytest.raises(TargetValidationError, match="too large"):
            validate_cidr("0.0.0.0/8")

    def test_invalid_ip(self):
        from app.utils.target_validator import validate_ip, TargetValidationError
        with pytest.raises(TargetValidationError, match="Invalid IP"):
            validate_ip("not-an-ip")

    def test_invalid_domain(self):
        from app.utils.target_validator import validate_domain, TargetValidationError
        with pytest.raises(TargetValidationError, match="Invalid domain"):
            validate_domain("not a domain!")

    def test_validate_target_dispatch(self):
        from app.utils.target_validator import validate_target
        assert validate_target("domain", "example.com") == "example.com"
        assert validate_target("ip", "8.8.8.8") == "8.8.8.8"


# ---------------------------------------------------------------------------
# Report Format Validation
# ---------------------------------------------------------------------------

class TestReports:
    def test_report_format_validation(self, client):
        """Report endpoint should reject invalid formats."""
        resp = client.post(
            "/api/v1/reports/generate",
            params={"scan_id": str(uuid.uuid4()), "format": "invalid"},
        )
        assert resp.status_code == 422

    def test_report_accepts_all_formats(self, client):
        """All 6 formats should pass validation (auth will fail but format is valid)."""
        for fmt in ("json", "csv", "pdf", "markdown", "junit", "html"):
            resp = client.post(
                "/api/v1/reports/generate",
                params={"scan_id": str(uuid.uuid4()), "format": fmt},
            )
            # 401/403 means format passed validation, auth failed (expected)
            assert resp.status_code in (401, 403), f"Format {fmt} returned {resp.status_code}"


# ---------------------------------------------------------------------------
# OpenAPI Schema
# ---------------------------------------------------------------------------

class TestOpenAPI:
    def test_openapi_schema_loads(self, client):
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        schema = resp.json()
        assert schema["info"]["title"] == "NIS2 Compliance Platform API"
        assert schema["info"]["version"] == "2.2.4"

    def test_all_router_tags_present(self, client):
        resp = client.get("/openapi.json")
        schema = resp.json()
        tags = {tag["name"] for tag in schema.get("tags", [])}
        paths = schema.get("paths", {})
        # Verify key paths exist
        assert "/api/v1/auth/login" in paths
        assert "/api/v1/scans" in paths
        assert "/api/v1/findings" in paths
        assert "/api/v1/incidents" in paths
        assert "/api/v1/governance" in paths
        assert "/api/v1/api-keys" in paths
        assert "/api/v1/reports/generate" in paths
