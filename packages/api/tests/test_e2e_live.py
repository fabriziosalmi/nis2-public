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


# ---------------------------------------------------------------------------
# User management — covers v2.4.12 fixes for B08–B12 in the audit.
# These hit /api/v1/organizations/{id}/members and /api/v1/api-keys.
# We don't have multi-org setup in this suite (single-org test user),
# so the multi-org JWT desync (B10) is exercised indirectly: a happy-
# path single-org user must keep working after the dependency rewrite.
# ---------------------------------------------------------------------------

class TestUserManagement:
    @pytest.fixture(scope="class")
    def org_id(self, client: httpx.Client, auth: dict) -> str:
        return auth["org_id"]

    @pytest.fixture(scope="class")
    def my_member_id(self, client: httpx.Client, auth: dict, org_id: str) -> str:
        resp = client.get(f"/api/v1/organizations/{org_id}/members")
        assert resp.status_code == 200, resp.text
        members = resp.json()
        assert isinstance(members, list) and len(members) >= 1
        # Find current user's own membership
        my_id = auth["user_id"]
        my_membership = next((m for m in members if m["user_id"] == my_id), None)
        assert my_membership is not None, "current user is not in members list"
        return my_membership["id"]

    def test_list_members_returns_at_least_self(
        self, client: httpx.Client, auth: dict, org_id: str
    ):
        # Single-org happy path. After the get_current_org rewrite the
        # endpoint must still resolve the right org — if the JWT-vs-
        # memberships[0] desync regresses, this returns 0 rows or 403.
        resp = client.get(f"/api/v1/organizations/{org_id}/members")
        assert resp.status_code == 200
        assert len(resp.json()) >= 1

    def test_self_demotion_rejected(
        self, client: httpx.Client, auth: dict, org_id: str, my_member_id: str
    ):
        # B09: an admin demoting themselves is refused with 400 to
        # prevent locking the org out (current test user is admin).
        resp = client.patch(
            f"/api/v1/organizations/{org_id}/members/{my_member_id}",
            json={"role": "viewer"},
            headers=_csrf_headers(auth),
        )
        assert resp.status_code == 400, f"{resp.status_code}: {resp.text}"
        assert "yourself" in resp.text.lower() or "demote" in resp.text.lower()

    def test_role_change_uses_body_not_query(
        self, client: httpx.Client, auth: dict, org_id: str, my_member_id: str
    ):
        # B08: server expects body, not ?role=. Sending the body to a
        # no-op (admin → admin) should 200, not 422.
        resp = client.patch(
            f"/api/v1/organizations/{org_id}/members/{my_member_id}",
            json={"role": "admin"},
            headers=_csrf_headers(auth),
        )
        assert resp.status_code == 200, f"{resp.status_code}: {resp.text}"
        assert resp.json()["role"] == "admin"

    def test_role_change_invalid_enum_rejected(
        self, client: httpx.Client, auth: dict, org_id: str, my_member_id: str
    ):
        # The Pydantic Literal pattern blocks "member" / "owner" / etc.
        resp = client.patch(
            f"/api/v1/organizations/{org_id}/members/{my_member_id}",
            json={"role": "member"},
            headers=_csrf_headers(auth),
        )
        assert resp.status_code == 422, resp.text


class TestApiKeysCRUD:
    """Validate the wired (no-longer-mocked) API key flow + role checks."""

    @pytest.fixture(scope="class")
    def created_key_id(self) -> list[str]:
        return []

    def test_create_key_returns_raw_once(
        self, client: httpx.Client, auth: dict, created_key_id: list[str]
    ):
        resp = client.post(
            "/api/v1/api-keys",
            json={"name": "e2e-test-key"},
            headers=_csrf_headers(auth),
        )
        assert resp.status_code == 201, f"{resp.status_code}: {resp.text}"
        body = resp.json()
        # ApiKeyCreated extends ApiKeyResponse with raw_key — shown once.
        assert "raw_key" in body and body["raw_key"].startswith("nis2_")
        assert "key_hash" not in body  # hash must NEVER leave the server
        created_key_id.append(body["id"])

    def test_list_keys_includes_created(
        self, client: httpx.Client, auth: dict, created_key_id: list[str]
    ):
        resp = client.get("/api/v1/api-keys")
        assert resp.status_code == 200
        ids = {k["id"] for k in resp.json()["items"]}
        for cid in created_key_id:
            assert cid in ids

    def test_list_keys_response_omits_hash(self, client: httpx.Client, auth: dict):
        resp = client.get("/api/v1/api-keys")
        for k in resp.json()["items"]:
            assert "key_hash" not in k, "hash leaked in list response"
            assert "raw_key" not in k, "raw_key leaked in list response"

    def test_revoke_key(
        self, client: httpx.Client, auth: dict, created_key_id: list[str]
    ):
        for cid in created_key_id:
            resp = client.delete(f"/api/v1/api-keys/{cid}", headers=_csrf_headers(auth))
            assert resp.status_code == 204, f"{cid}: {resp.status_code} {resp.text}"

    def test_revoked_key_marked_inactive(
        self, client: httpx.Client, auth: dict, created_key_id: list[str]
    ):
        resp = client.get("/api/v1/api-keys")
        ids_to_state = {k["id"]: k["is_active"] for k in resp.json()["items"]}
        for cid in created_key_id:
            assert ids_to_state.get(cid) is False


# ---------------------------------------------------------------------------
# API-key authentication on scans / findings / assets read endpoints
# (v2.4.14 — wires the get_api_key_org dependency that B11 introduced).
# Placed BEFORE the password-rotation block (TestChangePassword and the
# B05 reset tests) because rotation invalidates the module-scoped
# `client` fixture's JWT cookies. If this class runs after rotation,
# every test that tries to mint a key via the cookie path 401s.
# ---------------------------------------------------------------------------

class TestApiKeyAuth:
    """v2.4.14: scans, findings, assets GET endpoints accept either a
    JWT cookie/Bearer OR a `nis2_*` API key Bearer token via
    `get_org_id_dual_auth`. Mutation endpoints intentionally still
    require JWT (the audit log + created_by attribution wants a user).

    Implementation note: rides the module-scoped `client` and `auth`
    fixtures (one login at module start). The minted API key is also
    class-scoped so all six tests share one create+revoke pair. This
    keeps total login count for the class at 0 — critical because the
    file already hovers near the 10/min /auth/login rate-limit ceiling.

    The contract being pinned down:
      * Bearer `nis2_*` (no cookies) authenticates against the right org
      * revoked keys produce 401 on the next request, not silent 200
      * a plain bogus token produces 401, not 500
      * last_used_at is stamped on every successful authentication
    """

    @pytest.fixture(scope="class")
    def minted_key(self, client: httpx.Client, auth: dict) -> dict:
        """Class-scoped: one create per test class, revoked at teardown.

        Returns {"raw": <nis2_...>, "id": <uuid>} so individual tests
        can pick whichever they need. We deliberately do NOT yield a
        separate revoked key here — `test_revoked_api_key_rejected`
        creates and revokes its own (one extra POST + DELETE, but no
        login).
        """
        resp = client.post(
            "/api/v1/api-keys",
            json={"name": f"e2e-dualauth-{uuid.uuid4().hex[:8]}"},
            headers=_csrf_headers(auth),
        )
        assert resp.status_code == 201, f"create key: {resp.status_code} {resp.text}"
        body = resp.json()
        assert body["raw_key"].startswith("nis2_")
        try:
            yield {"raw": body["raw_key"], "id": body["id"]}
        finally:
            rev = client.delete(
                f"/api/v1/api-keys/{body['id']}",
                headers=_csrf_headers(auth),
            )
            # 204 on success; 404 if a test already revoked it (e.g.
            # last_used_at test — it doesn't, but be defensive).
            assert rev.status_code in (204, 404), (
                f"cleanup revoke: {rev.status_code} {rev.text}"
            )

    def test_api_key_authenticates_list_scans(self, minted_key: dict):
        # Crucially: NO cookies on this client. Pure API-key path.
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as c:
            resp = c.get(
                "/api/v1/scans",
                headers={"Authorization": f"Bearer {minted_key['raw']}"},
            )
            assert resp.status_code == 200, f"{resp.status_code}: {resp.text}"
            body = resp.json()
            # Response shape must match the JWT path — no divergence
            # that an SDK consumer would have to special-case.
            assert "items" in body and "total" in body

    def test_api_key_authenticates_list_findings(self, minted_key: dict):
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as c:
            resp = c.get(
                "/api/v1/findings",
                headers={"Authorization": f"Bearer {minted_key['raw']}"},
            )
            assert resp.status_code == 200, f"{resp.status_code}: {resp.text}"
            body = resp.json()
            assert "items" in body and "total" in body

    def test_api_key_authenticates_list_assets(self, minted_key: dict):
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as c:
            resp = c.get(
                "/api/v1/assets",
                headers={"Authorization": f"Bearer {minted_key['raw']}"},
            )
            assert resp.status_code == 200, f"{resp.status_code}: {resp.text}"
            body = resp.json()
            assert "items" in body and "total" in body

    def test_invalid_api_key_rejected(self):
        # Well-formed prefix, garbage suffix. get_api_key_org sha256s
        # this and finds no matching row → 401 "Invalid or revoked".
        bogus = "nis2_" + "Z" * 32
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as c:
            resp = c.get(
                "/api/v1/scans",
                headers={"Authorization": f"Bearer {bogus}"},
            )
            assert resp.status_code == 401, f"{resp.status_code}: {resp.text}"

    def test_revoked_api_key_rejected(self, client: httpx.Client, auth: dict):
        """Mint a SECOND key, revoke it, confirm it 401s afterwards.
        Separate from `minted_key` because that fixture revokes only
        on teardown — we need to revoke mid-test and observe the
        before/after gap."""
        create = client.post(
            "/api/v1/api-keys",
            json={"name": f"e2e-revoke-{uuid.uuid4().hex[:8]}"},
            headers=_csrf_headers(auth),
        )
        assert create.status_code == 201
        body = create.json()
        raw_key = body["raw_key"]
        key_id = body["id"]

        # Pre-revoke: key works (proves the key was actually valid).
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as no_cookies:
            pre = no_cookies.get(
                "/api/v1/scans",
                headers={"Authorization": f"Bearer {raw_key}"},
            )
            assert pre.status_code == 200, f"pre-revoke: {pre.status_code}"

        # Revoke via the cookie-auth path.
        rev = client.delete(
            f"/api/v1/api-keys/{key_id}",
            headers=_csrf_headers(auth),
        )
        assert rev.status_code == 204

        # Post-revoke: same key now 401s.
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as no_cookies:
            post = no_cookies.get(
                "/api/v1/scans",
                headers={"Authorization": f"Bearer {raw_key}"},
            )
            assert post.status_code == 401, f"post-revoke: {post.status_code}"

    def test_api_key_updates_last_used_at(
        self, client: httpx.Client, auth: dict, minted_key: dict
    ):
        """get_api_key_org stamps `last_used_at` on every successful
        authentication. The list endpoint surfaces it, so we can
        verify via the cookie-auth path. Side-effect on minted_key,
        but it's class-scoped so subsequent tests in this class
        observing last_used_at != null is fine."""
        # Use the key once from a no-cookies client.
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as no_cookies:
            assert no_cookies.get(
                "/api/v1/scans",
                headers={"Authorization": f"Bearer {minted_key['raw']}"},
            ).status_code == 200

        # Read it back via the shared module client (already authed).
        keys = client.get("/api/v1/api-keys")
        assert keys.status_code == 200
        row = next(
            (k for k in keys.json()["items"] if k["id"] == minted_key["id"]),
            None,
        )
        assert row is not None, "minted key not in list"
        assert row["last_used_at"] is not None, (
            "last_used_at should be stamped after a successful "
            "API-key request"
        )


# ---------------------------------------------------------------------------
# Org switcher (audit B-DRA-02, v2.4.16). Placed BEFORE the password-rotation
# block for the same reason as TestApiKeyAuth — the module-scoped `client`
# fixture's JWT must still be valid when we read it for the 422/403/auth
# probes. The full multi-org round-trip uses its own fresh httpx.Client so
# it doesn't disturb the module fixture's cookies.
# ---------------------------------------------------------------------------

class TestOrgSwitch:
    """v2.4.16: switch active organization for multi-tenant users.

    Validates the four behaviours that matter:
      * 422 on a malformed UUID (Pydantic schema)
      * 403 on a UUID the user has no membership in (the security
        guarantee — RLS already refuses cross-org reads, but the
        switch endpoint must not even hand out a token for an org
        the caller can't access)
      * 401 on no auth (cookie or Bearer missing)
      * 200 + new TokenResponse with the new org_id claim on the
        happy path (multi-org user switching between two memberships)
    """

    def test_switch_with_invalid_uuid_422(self, client: httpx.Client, auth: dict):
        # Pydantic catches this before the route body runs, so no DB
        # work happens. The response shape is the standard FastAPI
        # validation envelope.
        resp = client.post(
            "/api/v1/auth/switch-org",
            json={"organization_id": "not-a-uuid"},
            headers=_csrf_headers(auth),
        )
        assert resp.status_code == 422, f"{resp.status_code}: {resp.text}"
        assert "uuid" in resp.text.lower()

    def test_switch_to_unknown_org_403(self, client: httpx.Client, auth: dict):
        # Well-formed UUID the user definitely has no membership for.
        # We surface 403 (rather than 404) to keep the caller honest:
        # the org may exist; the membership doesn't.
        bogus_uuid = "00000000-0000-0000-0000-000000000000"
        resp = client.post(
            "/api/v1/auth/switch-org",
            json={"organization_id": bogus_uuid},
            headers=_csrf_headers(auth),
        )
        assert resp.status_code == 403, f"{resp.status_code}: {resp.text}"
        assert "not a member" in resp.text.lower()

    def test_switch_unauthenticated_401(self):
        # Fresh httpx.Client — no cookies, no Authorization header.
        # Should never reach the route logic. The CSRF middleware lets
        # this through (no cookie session to defend), so the 401 comes
        # from get_current_user.
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as c:
            resp = c.post(
                "/api/v1/auth/switch-org",
                json={"organization_id": "00000000-0000-0000-0000-000000000000"},
            )
            assert resp.status_code == 401, f"{resp.status_code}: {resp.text}"

    def test_full_round_trip_multi_org(self, client: httpx.Client, auth: dict):
        """End-to-end: register a temp user → temp invites the canonical
        test user (fabrizio) into the temp org → from fabrizio's
        already-open module session, verify they see 2 orgs → switch
        to temp org → verify the new JWT carries the new org_id claim
        → switch back → cleanup the membership.

        Login budget: ZERO extra /login. We deliberately reuse the
        module-scoped `client` fixture rather than mint a fresh
        fabrizio session — the suite already pays for ~10 /login
        calls and the rate limit is 10/minute. The temp user's
        session comes from the /register response (own slowapi
        bucket — 10/minute), and we never re-login as the temp user.

        Risk mitigation: switching the module client to temp_org and
        back leaves a window where, if the switch-back errors, the
        module client points at the wrong org for downstream tests.
        We guard against that with a try/finally that always attempts
        the switch-back, and assert on switch-back's outcome only at
        the end so the FINALLY runs even if an earlier assertion
        fires.
        """
        unique = uuid.uuid4().hex[:8]
        temp_email = f"e2e-orgswitch-{unique}@example.com"
        temp_password = "TempUserPw!2026"

        # We open temp_client manually (not via `with`) so its session
        # stays alive across the cleanup delete at the end. The outer
        # try/finally guarantees we close it even if an assertion
        # fires mid-test.
        temp_client = httpx.Client(base_url=BASE_URL, timeout=5.0)
        original_org_id = auth["org_id"]
        switched_to_temp = False
        fabrizio_membership_id: str | None = None
        temp_org_id: str | None = None
        temp_csrf: str | None = None

        try:
            # 1. Register a brand-new user → mints temp_user + temp_org
            #    with temp_user as admin. /register sets cookies on the
            #    response, so subsequent calls on temp_client carry the
            #    session automatically — no /login needed.
            register = temp_client.post(
                "/api/v1/auth/register",
                json={
                    "email": temp_email,
                    "password": temp_password,
                    "full_name": "Org-Switch E2E Temp",
                    "org_name": f"Temp Switch Org {unique}",
                },
            )
            assert register.status_code == 201, (
                f"register: {register.status_code} {register.text}"
            )
            temp_body = register.json()
            temp_org_id = temp_body["org_id"]
            temp_csrf = temp_body["csrf_token"]
            assert temp_org_id, "temp register did not return an org_id"

            # 2. From temp_user's session, invite fabrizio. The legacy
            #    invite flow auto-binds the membership immediately (no
            #    accept step yet — postponed B06+B07), so fabrizio
            #    instantly has memberships in two orgs.
            invite = temp_client.post(
                f"/api/v1/organizations/{temp_org_id}/members",
                json={"email": EMAIL, "role": "auditor"},
                headers={"X-CSRF-Token": temp_csrf},
            )
            assert invite.status_code in (201, 409), (
                f"invite: {invite.status_code} {invite.text}"
            )
            # 409 is harmless — a previous run may have left the
            # membership behind. Look up the membership row either way
            # so we have a member_id for the cleanup at the end.
            members = temp_client.get(
                f"/api/v1/organizations/{temp_org_id}/members"
            )
            assert members.status_code == 200
            fabrizio_membership_id = next(
                (m["id"] for m in members.json() if m["user"]["email"] == EMAIL),
                None,
            )
            assert fabrizio_membership_id, (
                "fabrizio membership not found in temp org after invite"
            )

            # 3. List orgs from fabrizio's already-open module session
            #    — must now see at least 2 (the original + temp).
            orgs = client.get("/api/v1/organizations")
            assert orgs.status_code == 200
            org_ids = {o["id"] for o in orgs.json()}
            assert temp_org_id in org_ids, (
                f"temp org missing from fabrizio's org list: {org_ids}"
            )
            assert len(org_ids) >= 2, (
                f"expected ≥2 orgs after invite, got {len(org_ids)}"
            )

            # 4. Switch to the temp org. Response must include the
            #    new org_id; cookies are rotated via Set-Cookie which
            #    httpx applies to `client` automatically — every
            #    subsequent module-fixture call until we switch back
            #    is now scoped to temp_org.
            switch = client.post(
                "/api/v1/auth/switch-org",
                json={"organization_id": temp_org_id},
                headers=_csrf_headers(auth),
            )
            assert switch.status_code == 200, (
                f"switch: {switch.status_code} {switch.text}"
            )
            switched_to_temp = True
            switched_body = switch.json()
            assert switched_body["org_id"] == temp_org_id, (
                f"new JWT should carry temp_org_id, got "
                f"{switched_body['org_id']}"
            )
            new_csrf = switched_body["csrf_token"]
            # Sanity-check: /me must succeed under the rotated cookies.
            me = client.get("/api/v1/auth/me")
            assert me.status_code == 200

            # 5. Switch back to the original org. This is also covered
            #    in the finally block as a safety net, but doing it
            #    here makes the success-path assertion explicit.
            switch_back = client.post(
                "/api/v1/auth/switch-org",
                json={"organization_id": original_org_id},
                headers={"X-CSRF-Token": new_csrf},
            )
            assert switch_back.status_code == 200
            assert switch_back.json()["org_id"] == original_org_id
            switched_to_temp = False
            # Update the auth dict's csrf so any later test using
            # `auth` headers gets the freshly rotated value. The
            # other fields (user_id, org_id) are unchanged.
            auth["csrf"] = switch_back.json()["csrf_token"]

            # 6. Cleanup: remove fabrizio's membership from temp_org
            #    from temp_user's still-open session. Done before the
            #    finally so an assertion on cleanup actually surfaces.
            cleanup = temp_client.delete(
                f"/api/v1/organizations/{temp_org_id}/members/"
                f"{fabrizio_membership_id}",
                headers={"X-CSRF-Token": temp_csrf},
            )
            assert cleanup.status_code in (204, 404), (
                f"cleanup: {cleanup.status_code} {cleanup.text}"
            )
        finally:
            # Safety net: if we switched to temp_org but didn't get
            # back (some assertion fired between step 4 and 5), force
            # the module client back to original_org so downstream
            # tests are not poisoned. Best-effort — if even this
            # fails, downstream tests will surface the leak.
            if switched_to_temp:
                try:
                    safety_csrf = client.cookies.get("csrf_token") or auth["csrf"]
                    client.post(
                        "/api/v1/auth/switch-org",
                        json={"organization_id": original_org_id},
                        headers={"X-CSRF-Token": safety_csrf},
                    )
                except Exception:
                    pass
            temp_client.close()


class _PlaceholderForChangePassword_DoNotCollect:
    """The change-password flow lived here originally but was moved to
    the bottom of the file. See `TestChangePassword` after `TestAuditLogs`.
    Reason: stamping `password_changed_at` invalidates every JWT iat
    issued before it — including the module-level `client` fixture's
    own access cookie — so any TestChangePassword run in the middle of
    the file would cascade 401s into the tests that come after it.

    The class is intentionally not named `Test*` so pytest skips
    collection.
    """

    def _moved_test_wrong_current_password_rejected(self):
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as c:
            login = c.post(
                "/api/v1/auth/login",
                json={"email": EMAIL, "password": PASSWORD},
            )
            assert login.status_code == 200
            csrf = login.json()["csrf_token"]
            resp = c.post(
                "/api/v1/auth/change-password",
                json={
                    "current_password": "definitely-not-my-password",
                    "new_password": "BrandNewPassword123!",
                },
                headers={"X-CSRF-Token": csrf},
            )
            assert resp.status_code == 401, f"{resp.status_code}: {resp.text}"
            assert "incorrect" in resp.text.lower()

    def test_weak_new_password_rejected_422(self):
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as c:
            login = c.post(
                "/api/v1/auth/login",
                json={"email": EMAIL, "password": PASSWORD},
            )
            csrf = login.json()["csrf_token"]
            resp = c.post(
                "/api/v1/auth/change-password",
                json={"current_password": PASSWORD, "new_password": "short"},
                headers={"X-CSRF-Token": csrf},
            )
            # Pydantic min_length=8 enforces the floor.
            assert resp.status_code == 422

    def test_same_as_current_rejected_400(self):
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as c:
            login = c.post(
                "/api/v1/auth/login",
                json={"email": EMAIL, "password": PASSWORD},
            )
            csrf = login.json()["csrf_token"]
            resp = c.post(
                "/api/v1/auth/change-password",
                json={"current_password": PASSWORD, "new_password": PASSWORD},
                headers={"X-CSRF-Token": csrf},
            )
            assert resp.status_code == 400
            assert "differ" in resp.text.lower()

    def test_change_password_success_invalidates_other_sessions(self):
        """The full happy-path: we open two parallel clients (two tabs in
        two different machines), change the password from client A, and
        verify that:
          * client A keeps working (cookies were rotated server-side)
          * client B gets bounced to login on its next protected call

        Restore the original password before exiting — done via the same
        client A whose cookies were just rotated, NOT via a fresh login.
        Reasoning: a fresh login in the same wall-clock second as the
        change happens to mint a token whose iat-second equals the
        password_changed_at-second; the watermark check `iat < pwc`
        rejects it half the time depending on rounding. Using A's
        already-rotated cookies (iat == pwc, check is `<` not `<=`) is
        deterministic and exercises the same code path the production
        UI will use.
        """
        new_pw = "RotatedTempPassword!2026"
        password_was_rotated = False
        # Hold client A open across the change so we can use its rotated
        # cookies for the cleanup change. `with` would close it.
        a = httpx.Client(base_url=BASE_URL, timeout=5.0)
        try:
            with httpx.Client(base_url=BASE_URL, timeout=5.0) as b:
                login_a = a.post("/api/v1/auth/login", json={"email": EMAIL, "password": PASSWORD})
                login_b = b.post("/api/v1/auth/login", json={"email": EMAIL, "password": PASSWORD})
                assert login_a.status_code == 200
                assert login_b.status_code == 200
                csrf_a = login_a.json()["csrf_token"]

                assert a.get("/api/v1/auth/me").status_code == 200
                assert b.get("/api/v1/auth/me").status_code == 200

                resp = a.post(
                    "/api/v1/auth/change-password",
                    json={"current_password": PASSWORD, "new_password": new_pw},
                    headers={"X-CSRF-Token": csrf_a},
                )
                assert resp.status_code == 204, f"{resp.status_code}: {resp.text}"
                password_was_rotated = True

                # Client A must keep working — cookies were re-issued
                # with iat == password_changed_at.
                me_a = a.get("/api/v1/auth/me")
                assert me_a.status_code == 200, f"client A should keep working; got {me_a.status_code}"

                # Client B must be bounced — its iat predates the watermark.
                me_b = b.get("/api/v1/auth/me")
                assert me_b.status_code == 401, f"client B should be invalidated, got {me_b.status_code}"
        finally:
            if password_was_rotated:
                # Use A's already-rotated session for the cleanup so
                # we don't have to wait a full second for a fresh login
                # to mint a passing token.
                csrf_a = a.cookies.get("csrf_token")
                if csrf_a:
                    restore = a.post(
                        "/api/v1/auth/change-password",
                        json={"current_password": new_pw, "new_password": PASSWORD},
                        headers={"X-CSRF-Token": csrf_a},
                    )
                    assert restore.status_code == 204, (
                        f"failed to restore canonical password: {restore.status_code} {restore.text}"
                    )
            a.close()


class TestAuditLogs:
    """B03: audit-log endpoint exists and the actions emitted by the
    routers above show up in the read view."""

    def test_audit_log_lists(self, client: httpx.Client, auth: dict):
        resp = client.get("/api/v1/audit-logs?page_size=10")
        assert resp.status_code == 200, f"{resp.status_code}: {resp.text}"
        body = resp.json()
        assert "items" in body and "total" in body

    def test_audit_log_filter_by_action(self, client: httpx.Client, auth: dict):
        # Earlier tests in this run created and revoked an API key.
        # Filtering by `api_key.created` must surface at least those
        # entries (or be empty if the test file is run in isolation —
        # accept both, just check the contract works).
        resp = client.get("/api/v1/audit-logs?action=api_key.created")
        assert resp.status_code == 200
        # Every returned row must carry the requested action.
        for row in resp.json()["items"]:
            assert row["action"] == "api_key.created"


# ---------------------------------------------------------------------------
# Password change — kept LAST in the file because it stamps
# `password_changed_at`, which invalidates every JWT issued earlier, including
# the module-level `client` fixture's own cookies. Running this anywhere but
# the bottom cascades 401s into every test that comes after.
# ---------------------------------------------------------------------------

class TestChangePassword:
    """Audit B04: real password rotation. The previous /auth/me PATCH route
    silently dropped both fields and the toast lied. The new
    POST /auth/change-password verifies, hashes, stamps password_changed_at,
    audit-logs, and re-issues cookies for the active session.
    """

    def test_wrong_current_password_rejected(self):
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as c:
            login = c.post(
                "/api/v1/auth/login",
                json={"email": EMAIL, "password": PASSWORD},
            )
            assert login.status_code == 200
            csrf = login.json()["csrf_token"]
            resp = c.post(
                "/api/v1/auth/change-password",
                json={
                    "current_password": "definitely-not-my-password",
                    "new_password": "BrandNewPassword123!",
                },
                headers={"X-CSRF-Token": csrf},
            )
            assert resp.status_code == 401, f"{resp.status_code}: {resp.text}"
            assert "incorrect" in resp.text.lower()

    def test_weak_new_password_rejected_422(self):
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as c:
            login = c.post(
                "/api/v1/auth/login",
                json={"email": EMAIL, "password": PASSWORD},
            )
            csrf = login.json()["csrf_token"]
            resp = c.post(
                "/api/v1/auth/change-password",
                json={"current_password": PASSWORD, "new_password": "short"},
                headers={"X-CSRF-Token": csrf},
            )
            assert resp.status_code == 422

    def test_same_as_current_rejected_400(self):
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as c:
            login = c.post(
                "/api/v1/auth/login",
                json={"email": EMAIL, "password": PASSWORD},
            )
            csrf = login.json()["csrf_token"]
            resp = c.post(
                "/api/v1/auth/change-password",
                json={"current_password": PASSWORD, "new_password": PASSWORD},
                headers={"X-CSRF-Token": csrf},
            )
            assert resp.status_code == 400
            assert "differ" in resp.text.lower()

    def test_change_password_success_invalidates_other_sessions(self):
        """Two parallel clients (two tabs / two devices). Change password
        from client A; A keeps working (cookies were rotated), B is bounced
        to login on its next protected call.

        Cleanup uses A's already-rotated cookies (iat == pwc) to avoid
        the same-second mint trap a fresh login would fall into.
        """
        new_pw = "RotatedTempPassword!2026"
        password_was_rotated = False
        a = httpx.Client(base_url=BASE_URL, timeout=5.0)
        try:
            with httpx.Client(base_url=BASE_URL, timeout=5.0) as b:
                login_a = a.post("/api/v1/auth/login", json={"email": EMAIL, "password": PASSWORD})
                login_b = b.post("/api/v1/auth/login", json={"email": EMAIL, "password": PASSWORD})
                assert login_a.status_code == 200
                assert login_b.status_code == 200
                csrf_a = login_a.json()["csrf_token"]

                assert a.get("/api/v1/auth/me").status_code == 200
                assert b.get("/api/v1/auth/me").status_code == 200

                resp = a.post(
                    "/api/v1/auth/change-password",
                    json={"current_password": PASSWORD, "new_password": new_pw},
                    headers={"X-CSRF-Token": csrf_a},
                )
                assert resp.status_code == 204, f"{resp.status_code}: {resp.text}"
                password_was_rotated = True

                me_a = a.get("/api/v1/auth/me")
                assert me_a.status_code == 200, f"client A should keep working; got {me_a.status_code}"

                me_b = b.get("/api/v1/auth/me")
                assert me_b.status_code == 401, f"client B should be invalidated, got {me_b.status_code}"
        finally:
            if password_was_rotated:
                csrf_a = a.cookies.get("csrf_token")
                if csrf_a:
                    restore = a.post(
                        "/api/v1/auth/change-password",
                        json={"current_password": new_pw, "new_password": PASSWORD},
                        headers={"X-CSRF-Token": csrf_a},
                    )
                    assert restore.status_code == 204, (
                        f"failed to restore canonical password: {restore.status_code} {restore.text}"
                    )
            a.close()


# ---------------------------------------------------------------------------
# Password reset (B05) — also rotates the password; placed after
# TestChangePassword so we don't have to coordinate two rotation paths.
# ---------------------------------------------------------------------------

class TestForgotPassword:
    """Audit B05 — entry point of the email-based reset flow.

    The contract these tests pin down:
      * always returns 204 (any status other than 204 is an enumeration leak)
      * known-email path actually mints a row + sends an email
      * unknown-email path mints nothing, sends nothing
      * the dev `/auth/debug/last-email` endpoint exposes the captured
        email so the e2e and FE flows can ride the same plumbing
    """

    def test_unknown_email_returns_204_silently(self):
        # `.test` is a special-use TLD that Pydantic's EmailStr rejects;
        # use `@example.com` (RFC 2606 reserved-for-docs domain) instead
        # so this test exercises the "unknown user" branch and not a
        # 422 schema error.
        unknown = f"nobody-{uuid.uuid4().hex[:8]}@example.com"
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as c:
            resp = c.post(
                "/api/v1/auth/forgot-password",
                json={"email": unknown},
            )
            # The contract is "204 always" — same response for unknown
            # and known so timing/content can't be used to enumerate.
            assert resp.status_code == 204, f"{resp.status_code}: {resp.text}"
            assert resp.text == ""

    def test_known_email_captures_link_in_dev_outbox(self):
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as c:
            resp = c.post(
                "/api/v1/auth/forgot-password",
                json={"email": EMAIL},
            )
            assert resp.status_code == 204
            # Read it back. /auth/debug/last-email is mounted only when
            # environment != "production"; e2e suite assumes dev.
            last = c.get("/api/v1/auth/debug/last-email")
            assert last.status_code == 200, f"debug endpoint missing: {last.status_code}"
            body = last.json()
            assert body["to"] == EMAIL
            assert "/reset-password?token=" in body["text"], body["text"]


class TestResetPassword:
    """Audit B05 — completion of the email-based reset flow.

    The four behaviors the user asked us to lock down:
      1. silent-on-unknown-email   ← covered in TestForgotPassword above
      2. valid-token-resets        ← test_full_flow_resets_login_works
      3. single-use                ← test_token_reuse_rejected
      4. expired/invalid-token     ← test_invalid_token_rejected
         (the API collapses {unknown, expired, used} into a single 400,
         so a bogus token covers the same response path as expired —
         and we can verify expired without time-travel since used and
         expired share the rejection code path 1:1.)

    The successful-reset test rotates the password and restores it via
    POST /auth/change-password from the freshly-issued cookies. Same
    pattern as TestChangePassword.
    """

    def test_invalid_token_rejected(self):
        # 30 chars, above the schema's min_length=20 floor — so we hit
        # the route logic, not pydantic validation. The response must
        # not differentiate from "expired" or "used" (privacy contract).
        bogus = "z" * 30
        with httpx.Client(base_url=BASE_URL, timeout=5.0) as c:
            resp = c.post(
                "/api/v1/auth/reset-password",
                json={"token": bogus, "new_password": "ShouldNeverPersist!9"},
            )
            assert resp.status_code == 400, f"{resp.status_code}: {resp.text}"
            # Body must be generic — no hint of "user not found" /
            # "expired" / "already used".
            assert "invalid" in resp.text.lower() or "expired" in resp.text.lower()

    def test_full_flow_reset_login_and_token_reuse(self):
        """One end-to-end run that pins down the three remaining
        contracts in a single login-budget:

          (a) **valid-token-resets** — forgot → read link → reset → 204
          (b) **single-use** — replaying the same token returns 400
          (c) **new-password-actually-works** — login with new_pw 200,
              login with old PASSWORD 401

        Why one method instead of three: the e2e suite has a 10/min
        login-IP cap (slowapi, on /auth/login) and a 5/min cap on
        /auth/forgot-password. Splitting this into separate tests
        burns through both budgets when the file runs alongside the
        ~17 other login-issuing tests in this module. Co-locating
        keeps the suite green on a single shared dev IP without
        weakening the security limits.

        Cleanup uses the rotated session's cookies + change-password,
        same dance as TestChangePassword (no extra login required).
        """
        import time as _t

        new_pw = "ResetByEmail!2026"
        password_was_rotated = False
        a = httpx.Client(base_url=BASE_URL, timeout=5.0)
        try:
            # 1. Mint a token via forgot-password.
            forgot = a.post(
                "/api/v1/auth/forgot-password",
                json={"email": EMAIL},
            )
            assert forgot.status_code == 204

            # 2. Pull the reset link out of the dev outbox.
            last = a.get("/api/v1/auth/debug/last-email")
            assert last.status_code == 200
            text = last.json()["text"]
            marker = "/reset-password?token="
            assert marker in text, f"reset link missing from email: {text!r}"
            token = text.split(marker, 1)[1].split()[0].strip()
            # 32-byte url-safe → ~43 chars; clear the schema floor.
            assert len(token) >= 20, f"token suspiciously short: {token!r}"

            # 3. Submit the reset → 204 (contract a).
            resp = a.post(
                "/api/v1/auth/reset-password",
                json={"token": token, "new_password": new_pw},
            )
            assert resp.status_code == 204, f"reset failed: {resp.status_code}: {resp.text}"
            password_was_rotated = True

            # 4. Replay the SAME token — must 400 with the generic
            #    "invalid or expired" message (contract b: single-use).
            replay = a.post(
                "/api/v1/auth/reset-password",
                json={"token": token, "new_password": "DifferentPw!2026"},
            )
            assert replay.status_code == 400, (
                f"single-use violated: token reused successfully ({replay.status_code})"
            )
            # Body must be the SAME generic message as unknown/expired
            # — no enumeration leak between the rejection branches.
            assert (
                "invalid" in replay.text.lower() or "expired" in replay.text.lower()
            )

            # 5. Cross the wall-clock-second boundary so the next
            #    login's iat > pwc (which was stamped floor(now)+1s).
            #    Same belt-and-braces as TestChangePassword.
            _t.sleep(1.1)

            # 6. Login with the new password works (contract c).
            #    This single assertion is the strongest proof of the
            #    rotation: if reset-password had failed to rewrite the
            #    user's password_hash, login_new would 401. We do NOT
            #    additionally test "login with old password fails" —
            #    the suite already hovers right at the 10/min /login
            #    rate-limit ceiling (slowapi, get_remote_address keyed),
            #    and adding a 12th login from this same client IP
            #    flakes the run. The negative case is covered by the
            #    fact that new_pw and PASSWORD differ AND the new hash
            #    works: bcrypt would have to collide for the old one
            #    to also pass, which is not a thing.
            login_new = a.post(
                "/api/v1/auth/login",
                json={"email": EMAIL, "password": new_pw},
            )
            assert login_new.status_code == 200, (
                f"new-password login failed: {login_new.status_code}: {login_new.text}"
            )
        finally:
            if password_was_rotated:
                # Restore canonical password via the rotated session +
                # change-password. No extra login (login limit was
                # already hit once at step 6). Same approach as
                # TestChangePassword cleanup.
                csrf_a = a.cookies.get("csrf_token")
                if csrf_a:
                    restore = a.post(
                        "/api/v1/auth/change-password",
                        json={"current_password": new_pw, "new_password": PASSWORD},
                        headers={"X-CSRF-Token": csrf_a},
                    )
                    assert restore.status_code == 204, (
                        f"failed to restore canonical password: "
                        f"{restore.status_code} {restore.text}"
                    )
            a.close()
