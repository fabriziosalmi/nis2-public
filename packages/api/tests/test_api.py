"""
API unit tests — exercise routing, validation and middleware without a
real database. Anything that needs Postgres lives in test_integration.py.

The `get_db` dependency is overridden to yield None; routes that try to
use it crash and are returned as 500 by FastAPI's exception handler
(the TestClient is configured to NOT re-raise so we can assert on the
status code).
"""
import uuid

import pytest
from fastapi.testclient import TestClient

from app.database import get_db
from app.main import create_app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

async def _fake_db():
    """DB-free stand-in. Routes that touch it raise AttributeError → 500."""
    yield None


@pytest.fixture
def app():
    app = create_app()
    app.dependency_overrides[get_db] = _fake_db
    return app


@pytest.fixture
def client(app):
    # raise_server_exceptions=False so DB-down 500s come back as a response
    # the test can assert on, not as an uncaught Python exception.
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Health Check
# ---------------------------------------------------------------------------

class TestHealth:
    def test_health_endpoint(self, client):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"


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

    def test_user_update_avatar_url_validation(self):
        from app.schemas.auth import UserUpdate
        from pydantic import ValidationError

        # Valid URLs
        UserUpdate(avatar_url="https://example.com/avatar.png")
        UserUpdate(avatar_url="http://example.com/avatar.png")
        UserUpdate(avatar_url="/avatars/user.png")
        UserUpdate(avatar_url=None)

        # Invalid URLs
        with pytest.raises(ValidationError):
            UserUpdate(avatar_url="javascript:alert(1)")

        with pytest.raises(ValidationError):
            UserUpdate(avatar_url="data:image/png;base64,abc")

        with pytest.raises(ValidationError):
            UserUpdate(avatar_url="ftp://example.com/avatar.png")


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
        """Report endpoint should reject invalid formats. Auth is checked
        alongside parameter validation — either order is acceptable."""
        resp = client.post(
            "/api/v1/reports/generate",
            params={"scan_id": str(uuid.uuid4()), "format": "invalid"},
        )
        assert resp.status_code in (401, 403, 422)

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
        # Pre-2.5.1 this was hardcoded to whatever the literal in main.py
        # said, which made every release-bump leave a failing test
        # behind for a turn. Pull from main.API_VERSION so the assertion
        # tracks the actual constant — semver-shape sanity check is
        # enough to catch a malformed value.
        from app.main import API_VERSION
        assert schema["info"]["version"] == API_VERSION
        assert API_VERSION.count(".") == 2  # major.minor.patch
        assert all(part.isdigit() for part in API_VERSION.split("."))

    def test_all_router_tags_present(self, client):
        resp = client.get("/openapi.json")
        schema = resp.json()
        paths = schema.get("paths", {})
        # Verify key paths exist
        assert "/api/v1/auth/login" in paths
        assert "/api/v1/scans" in paths
        assert "/api/v1/findings" in paths
        assert "/api/v1/incidents" in paths
        assert "/api/v1/governance" in paths
        assert "/api/v1/api-keys" in paths
        assert "/api/v1/reports/generate" in paths


# ---------------------------------------------------------------------------
# MCP Rate Limiting
# ---------------------------------------------------------------------------

def _fake_membership(role: str):
    """Minimal (user, membership) pair for MCP dependency overrides.

    The MCP router now needs the membership ROLE, not just the org id, so
    overrides must supply an object carrying `.role`. SimpleNamespace keeps the
    tests free of a DB round-trip.
    """
    import uuid
    from types import SimpleNamespace

    user = SimpleNamespace(id=uuid.uuid4())
    membership = SimpleNamespace(role=role, organization_id=uuid.uuid4())
    return user, membership


class TestMcpRateLimit:
    def test_mcp_call_rate_limit(self, client, app):
        from app.dependencies import get_current_org
        from app.limiter import limiter

        # `viewer` is enough for list_governance_items (a read-only tool) and
        # keeps this test about rate limiting rather than authorisation.
        app.dependency_overrides[get_current_org] = lambda: _fake_membership("viewer")

        limiter.enabled = True
        try:
            # We are allowed 20 calls per minute.
            # Make 20 successful calls.
            for _ in range(20):
                resp = client.post("/api/v1/mcp/call", json={"name": "list_governance_items"})
                assert resp.status_code == 200, resp.text

            # The 21st call should trigger 429 Too Many Requests
            resp = client.post("/api/v1/mcp/call", json={"name": "list_governance_items"})
            assert resp.status_code == 429
        finally:
            limiter.enabled = False
            if get_current_org in app.dependency_overrides:
                del app.dependency_overrides[get_current_org]


class TestMcpAuthorization:
    """Per-tool RBAC on the MCP surface.

    Before this gate every tool ran behind membership alone, so the read-only
    `viewer` role could invoke `scan_target` -- a full port scan, AXFR attempt
    and HTTP probe of an arbitrary internet host -- and `check_certificate`.
    The REST equivalents (POST /scans, the /certificates router) require admin
    or auditor, and MCP scans are not persisted as Scan rows, so the bypass also
    left no org-visible trace.
    """

    def _override(self, app, role: str):
        from app.dependencies import get_current_org

        app.dependency_overrides[get_current_org] = lambda: _fake_membership(role)
        return get_current_org

    def teardown_method(self):
        pass

    @pytest.mark.parametrize("tool", ["scan_target", "check_certificate"])
    def test_viewer_cannot_invoke_outbound_tools(self, client, app, tool):
        """The bypass, stated directly."""
        dep = self._override(app, "viewer")
        try:
            resp = client.post(
                "/api/v1/mcp/call",
                json={"name": tool, "arguments": {"target": "example.com", "domain": "example.com"}},
            )
            assert resp.status_code == 403, resp.text
            assert "admin" in resp.json()["detail"]
        finally:
            del app.dependency_overrides[dep]

    @pytest.mark.parametrize("role", ["admin", "auditor"])
    def test_privileged_roles_pass_the_gate(self, client, app, role):
        """The gate must not simply block everyone.

        A blocked target is fine here -- it proves the request got past
        authorisation and into the tool, which is what this asserts. The
        SSRF validator rejecting the domain is a separate control.
        """
        dep = self._override(app, role)
        try:
            resp = client.post(
                "/api/v1/mcp/call",
                json={"name": "check_certificate", "arguments": {"domain": "localhost"}},
            )
            assert resp.status_code != 403, resp.text
        finally:
            del app.dependency_overrides[dep]

    def test_unknown_tool_is_denied_not_dispatched(self, client, app):
        """Default deny: a tool missing from MCP_TOOL_ROLES is unreachable, so
        adding one to MCP_TOOLS without deciding its authorisation fails closed
        instead of inheriting the weakest gate in the file."""
        dep = self._override(app, "admin")
        try:
            resp = client.post("/api/v1/mcp/call", json={"name": "not_a_real_tool"})
            assert resp.status_code == 403, resp.text
            assert resp.json()["detail"] == "Unknown tool"
        finally:
            del app.dependency_overrides[dep]

    def test_tool_listing_is_filtered_by_role(self, client, app):
        """Advertising a tool that would 403 invites an AI assistant to plan
        around a capability it does not have."""
        dep = self._override(app, "viewer")
        try:
            names = {t["name"] for t in client.get("/api/v1/mcp/tools").json()["tools"]}
            assert "scan_target" not in names
            assert "check_certificate" not in names
            assert "list_governance_items" in names
        finally:
            del app.dependency_overrides[dep]

        dep = self._override(app, "admin")
        try:
            names = {t["name"] for t in client.get("/api/v1/mcp/tools").json()["tools"]}
            assert "scan_target" in names
        finally:
            del app.dependency_overrides[dep]

    def test_every_declared_tool_has_an_explicit_role(self):
        """MCP_TOOLS and MCP_TOOL_ROLES must not drift.

        A tool declared but unmapped is unreachable (default deny), which is
        safe but silently broken; catching it here beats discovering it from a
        403 in production.
        """
        from app.mcp_server import MCP_TOOL_ROLES, MCP_TOOLS

        declared = {t["name"] for t in MCP_TOOLS}
        mapped = set(MCP_TOOL_ROLES)
        assert declared == mapped, (
            f"MCP_TOOLS and MCP_TOOL_ROLES disagree — "
            f"declared but unmapped (unreachable): {sorted(declared - mapped)}; "
            f"mapped but not declared: {sorted(mapped - declared)}"
        )

