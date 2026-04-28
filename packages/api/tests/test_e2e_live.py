"""
End-to-end live integration tests against a running API.

Why a separate file from `test_integration.py`?
- `test_integration.py` boots the FastAPI app in-process with a Postgres
  service, which is good for CI but does NOT exercise the actual Docker
  stack (gateway routing, CORS, real cookies over the wire, the web
  package proxying via INTERNAL_API_URL, etc.).
- `test_e2e_live.py` hits an already-running stack (e.g. `make dev`) over
  HTTP. It catches a class of bugs the in-process suite cannot:
    * schema drift (DB migration not applied)         ← real example: pinned_ip column
    * Docker compose env vars (slowapi missing, etc)  ← real example: v2.4.4 hotfix
    * cookie/CSRF flow over real http                 ← double-submit middleware

Run with:
    E2E_LIVE_BASE_URL=http://localhost:8000 \
    E2E_LIVE_EMAIL=fabrizio.salmi@gmail.com \
    E2E_LIVE_PASSWORD=invaders \
    pytest packages/api/tests/test_e2e_live.py -v

Skipped automatically if those vars are not set so plain `pytest` stays green.
"""
from __future__ import annotations

import os
import uuid

import httpx
import pytest

BASE_URL = os.environ.get("E2E_LIVE_BASE_URL")
EMAIL = os.environ.get("E2E_LIVE_EMAIL")
PASSWORD = os.environ.get("E2E_LIVE_PASSWORD")

pytestmark = pytest.mark.skipif(
    not (BASE_URL and EMAIL and PASSWORD),
    reason="E2E_LIVE_BASE_URL / EMAIL / PASSWORD not set — skipping live e2e",
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client() -> httpx.Client:
    """A single httpx.Client per module — cookies persist across tests so we
    can do a real `login → use → logout` sequence."""
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as c:
        yield c


@pytest.fixture(scope="module")
def auth(client: httpx.Client) -> dict:
    """Log in once for the module and return the CSRF token. Subsequent
    tests rely on the cookies sticking on the shared client."""
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": EMAIL, "password": PASSWORD},
    )
    assert resp.status_code == 200, f"login failed: {resp.status_code} {resp.text}"
    body = resp.json()
    assert "access_token" in body
    assert "csrf_token" in body
    assert body["user"]["email"] == EMAIL
    # The HttpOnly access_token cookie is now on the client; csrf_token
    # cookie is readable, but we also keep the value here as a header.
    return {"csrf": body["csrf_token"], "user_id": body["user"]["id"], "org_id": body["org_id"]}


def _csrf_headers(auth: dict) -> dict:
    return {"X-CSRF-Token": auth["csrf"]}


# ---------------------------------------------------------------------------
# Smoke
# ---------------------------------------------------------------------------

class TestSmoke:
    def test_health(self, client: httpx.Client):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_openapi(self, client: httpx.Client):
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        assert resp.json()["info"]["title"] == "NIS2 Compliance Platform API"


# ---------------------------------------------------------------------------
# Auth — cookie flow
# ---------------------------------------------------------------------------

class TestAuth:
    def test_login_sets_httponly_cookies(self, client: httpx.Client):
        resp = client.post(
            "/api/v1/auth/login",
            json={"email": EMAIL, "password": PASSWORD},
        )
        assert resp.status_code == 200
        # Check the *raw* set-cookie headers — httpx merges them into the jar
        # and strips HttpOnly. We need to verify the server is sending it.
        set_cookies = resp.headers.get_list("set-cookie")
        assert any("access_token=" in c and "HttpOnly" in c for c in set_cookies), (
            f"access_token must be HttpOnly; got: {set_cookies}"
        )
        assert any("refresh_token=" in c and "HttpOnly" in c for c in set_cookies), (
            f"refresh_token must be HttpOnly; got: {set_cookies}"
        )
        # csrf_token must NOT be HttpOnly (the JS layer needs to read it)
        csrf = next((c for c in set_cookies if c.startswith("csrf_token=")), None)
        assert csrf is not None, "csrf_token cookie missing"
        assert "HttpOnly" not in csrf, "csrf_token must be readable by JS"

    def test_login_wrong_password(self, client: httpx.Client):
        # Use a bare client so we don't poison the shared session cookies
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as c:
            resp = c.post(
                "/api/v1/auth/login",
                json={"email": EMAIL, "password": "wrong-on-purpose"},
            )
            assert resp.status_code == 401

    def test_me_with_cookie(self, client: httpx.Client, auth: dict):
        resp = client.get("/api/v1/auth/me")
        assert resp.status_code == 200
        body = resp.json()
        assert body["email"] == EMAIL

    def test_me_without_cookie(self):
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as c:
            resp = c.get("/api/v1/auth/me")
            assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# CSRF — double-submit enforcement
# ---------------------------------------------------------------------------

class TestCSRF:
    """State-changing requests with a valid session cookie but missing /
    mismatched CSRF token must be rejected."""

    def test_post_without_csrf_token(self, client: httpx.Client, auth: dict):
        resp = client.post(
            "/api/v1/assets",
            json={"name": "no-csrf", "target_type": "domain", "target_value": "example.com"},
            # NB: deliberately NOT sending X-CSRF-Token
        )
        assert resp.status_code == 403, (
            f"expected 403 for missing CSRF, got {resp.status_code}: {resp.text}"
        )

    def test_post_with_wrong_csrf_token(self, client: httpx.Client, auth: dict):
        resp = client.post(
            "/api/v1/assets",
            json={"name": "wrong-csrf", "target_type": "domain", "target_value": "example.com"},
            headers={"X-CSRF-Token": "definitely-wrong"},
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Assets — full CRUD against live DB
# ---------------------------------------------------------------------------

class TestAssetsCRUD:
    """Full create/read/delete loop. The domain test is the *exact*
    regression for the v2.4.5 schema-drift bug (assets.pinned_ip missing)."""

    @pytest.fixture(scope="class")
    def created_ids(self) -> list[str]:
        return []

    def test_create_domain_asset(
        self, client: httpx.Client, auth: dict, created_ids: list[str]
    ):
        # Use a unique target value so re-running the suite never trips
        # the duplicate check.
        target = f"e2e-{uuid.uuid4().hex[:8]}.example.com"
        resp = client.post(
            "/api/v1/assets",
            json={"name": "e2e domain", "target_type": "domain", "target_value": target},
            headers=_csrf_headers(auth),
        )
        # 201 on success; if this is 500 with "column assets.pinned_ip does not
        # exist" you are looking at the schema-drift bug — run the alembic
        # migration / ALTER TABLE.
        assert resp.status_code == 201, f"{resp.status_code}: {resp.text}"
        body = resp.json()
        assert body["target_value"] == target
        assert body["target_type"] == "domain"
        # pinned_ip may be None if DNS resolution was skipped (e.g. example.com
        # resolves but resolver is mocked). The key invariant is the *field
        # exists* in the response — proving the model and DB are in sync.
        assert "pinned_ip" in body
        created_ids.append(body["id"])

    def test_create_ip_asset(
        self, client: httpx.Client, auth: dict, created_ids: list[str]
    ):
        resp = client.post(
            "/api/v1/assets",
            json={"name": "e2e ip", "target_type": "ip", "target_value": "8.8.8.8"},
            headers=_csrf_headers(auth),
        )
        assert resp.status_code == 201, f"{resp.status_code}: {resp.text}"
        created_ids.append(resp.json()["id"])

    def test_create_cidr_asset(
        self, client: httpx.Client, auth: dict, created_ids: list[str]
    ):
        resp = client.post(
            "/api/v1/assets",
            json={"name": "e2e cidr", "target_type": "cidr", "target_value": "203.0.113.0/24"},
            headers=_csrf_headers(auth),
        )
        assert resp.status_code == 201, f"{resp.status_code}: {resp.text}"
        created_ids.append(resp.json()["id"])

    @pytest.mark.parametrize(
        "target_type,target_value",
        [
            ("ip", "10.0.0.1"),         # RFC1918
            ("ip", "127.0.0.1"),        # loopback
            ("ip", "169.254.169.254"),  # cloud metadata
            ("domain", "localhost"),
            ("domain", "metadata.google.internal"),
            ("cidr", "192.168.0.0/16"), # private CIDR
        ],
    )
    def test_ssrf_blocked(
        self,
        client: httpx.Client,
        auth: dict,
        target_type: str,
        target_value: str,
    ):
        """SSRF guard must reject private/loopback/metadata targets — this
        is the layer that prevents a tenant from scanning your control plane."""
        resp = client.post(
            "/api/v1/assets",
            json={"name": "ssrf", "target_type": target_type, "target_value": target_value},
            headers=_csrf_headers(auth),
        )
        assert resp.status_code == 422, (
            f"{target_type}={target_value} should be 422, got {resp.status_code}: {resp.text}"
        )

    def test_list_assets_includes_created(
        self, client: httpx.Client, auth: dict, created_ids: list[str]
    ):
        resp = client.get("/api/v1/assets?page_size=100")
        assert resp.status_code == 200
        ids_in_list = {a["id"] for a in resp.json()["items"]}
        for cid in created_ids:
            assert cid in ids_in_list, f"created asset {cid} not visible in list"

    def test_delete_assets(
        self, client: httpx.Client, auth: dict, created_ids: list[str]
    ):
        for cid in created_ids:
            resp = client.delete(f"/api/v1/assets/{cid}", headers=_csrf_headers(auth))
            assert resp.status_code == 204, f"{cid}: {resp.status_code} {resp.text}"

    def test_deleted_assets_gone(
        self, client: httpx.Client, auth: dict, created_ids: list[str]
    ):
        resp = client.get("/api/v1/assets?page_size=100")
        assert resp.status_code == 200
        ids_in_list = {a["id"] for a in resp.json()["items"]}
        for cid in created_ids:
            assert cid not in ids_in_list, f"deleted asset {cid} still in list"


# ---------------------------------------------------------------------------
# Logout — cookies cleared, /me rejects
# ---------------------------------------------------------------------------

class TestLogout:
    def test_logout_then_me_rejected(self):
        # Fresh client so we don't pull down the module-level session
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as c:
            login = c.post(
                "/api/v1/auth/login",
                json={"email": EMAIL, "password": PASSWORD},
            )
            assert login.status_code == 200
            csrf = login.json()["csrf_token"]

            me = c.get("/api/v1/auth/me")
            assert me.status_code == 200

            logout = c.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf})
            assert logout.status_code in (200, 204)

            me_after = c.get("/api/v1/auth/me")
            assert me_after.status_code in (401, 403), (
                f"after logout /me must reject; got {me_after.status_code}"
            )
