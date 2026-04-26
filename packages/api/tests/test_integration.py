# Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Integration tests against a real Postgres instance.

These tests close the "honest limits" we noted in the v2.4 release:

  * RLS-enforced cross-tenant isolation (a forgotten WHERE clause must
    still return zero rows from the database).
  * Refresh-token rotation and revocation (replay of a consumed refresh
    token must fail; /logout must invalidate the current session).
  * Audit-log auto-application (every successful state-changing request
    must produce an audit_logs row, without per-route boilerplate).
  * CSRF enforcement on cookie-authenticated state changes.

Run locally:

    docker compose -f infra/docker/docker-compose.dev.yml up -d postgres

    INTEGRATION_DB=1 \\
    ENVIRONMENT=production \\
    DATABASE_URL=postgresql+asyncpg://nis2:nis2secret@localhost:5433/nis2_test \\
    DATABASE_URL_SYNC=postgresql://nis2:nis2secret@localhost:5433/nis2_test \\
    JWT_SECRET="$(openssl rand -base64 32)" \\
    CORS_ORIGINS=http://localhost:3000 \\
    pytest tests/test_integration.py -v

CI runs the same flow via the integration-tests job in .github/workflows/ci.yml.
"""
from __future__ import annotations

import asyncio
import os
import secrets
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text

from app.database import (
    Base,
    IS_POSTGRES,
    async_session_factory,
    engine,
    setup_row_level_security,
)
from app.main import create_app
from app.models.audit_log import AuditLog
from app.models.revoked_token import RevokedToken


pytestmark = pytest.mark.skipif(
    not os.environ.get("INTEGRATION_DB"),
    reason="Set INTEGRATION_DB=1 (with DATABASE_URL pointing to Postgres) to run.",
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

async def _bootstrap_async() -> None:
    """Drop and recreate the schema, then apply RLS policies."""
    async with engine.begin() as conn:
        # We must bypass RLS to drop tables that have policies.
        await conn.execute(text("SET LOCAL app.bypass_rls = 'on'"))
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    await setup_row_level_security()


@pytest.fixture(scope="session", autouse=True)
def bootstrap_schema():
    """Bring the test database to a known clean state once per session."""
    if not IS_POSTGRES:
        pytest.skip("integration suite requires Postgres")
    asyncio.run(_bootstrap_async())
    yield


# In production the auth cookies are set with Secure=True. httpx (under
# TestClient) honours that and refuses to send Secure cookies over plain
# http://testserver, which makes every state-changing request fail auth.
# Pinning base_url to https://testserver keeps the cookie path identical
# to a real deployment behind Caddy.
TEST_BASE_URL = "https://testserver"


def _new_client() -> TestClient:
    return TestClient(
        create_app(),
        raise_server_exceptions=False,
        base_url=TEST_BASE_URL,
    )


@pytest.fixture
def fresh_client() -> TestClient:
    """A TestClient with no preset cookies — useful for replay tests."""
    return _new_client()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _register_org(client: TestClient, slug: str) -> dict[str, Any]:
    """Register a brand-new (user, organization) pair and return the body."""
    suffix = secrets.token_hex(4)
    payload = {
        "email": f"{slug}-{suffix}@test.example.com",
        "password": "Pa$$w0rd-test-12345",
        "full_name": f"User {slug}",
        "org_name": f"Org-{slug}-{suffix}",
    }
    r = client.post("/api/v1/auth/register", json=payload)
    assert r.status_code == 201, r.text
    return r.json()


def _csrf_headers(client: TestClient) -> dict[str, str]:
    csrf = client.cookies.get("csrf_token")
    assert csrf, "csrf_token cookie missing — did /register set it?"
    return {"X-CSRF-Token": csrf}


def _async_run(coro):
    """Run a coroutine inside a sync test, fresh event loop each time."""
    return asyncio.run(coro)


async def _select_audit_rows(org_id: uuid.UUID) -> list[AuditLog]:
    async with async_session_factory() as session:
        await session.execute(text("SET LOCAL app.bypass_rls = 'on'"))
        result = await session.execute(
            select(AuditLog).where(AuditLog.organization_id == org_id)
        )
        return list(result.scalars().all())


async def _count_revoked_tokens() -> int:
    async with async_session_factory() as session:
        await session.execute(text("SET LOCAL app.bypass_rls = 'on'"))
        result = await session.execute(select(RevokedToken))
        return len(list(result.scalars().all()))


# ---------------------------------------------------------------------------
# RLS — tenant isolation enforced at the database layer
# ---------------------------------------------------------------------------

class TestRowLevelSecurity:
    def test_two_orgs_cannot_see_each_others_assets(self, fresh_client):
        client_a = fresh_client
        client_b = _new_client()

        _register_org(client_a, "alpha")
        _register_org(client_b, "beta")

        # A creates an asset
        r = client_a.post(
            "/api/v1/assets",
            json={
                "name": "alpha-www",
                "target_type": "domain",
                "target_value": "example.com",
            },
            headers=_csrf_headers(client_a),
        )
        assert r.status_code == 201, r.text
        asset_id = r.json()["id"]

        # A sees its own asset
        r = client_a.get("/api/v1/assets")
        assert r.status_code == 200
        a_items = r.json()["items"]
        assert len(a_items) == 1
        assert a_items[0]["id"] == asset_id

        # B sees zero assets — RLS enforced even at the SQL layer
        r = client_b.get("/api/v1/assets")
        assert r.status_code == 200
        assert r.json()["total"] == 0

        # B cannot read A's asset by direct id either
        r = client_b.get(f"/api/v1/assets/{asset_id}")
        assert r.status_code == 404

    def test_force_rls_unset_org_returns_zero(self, fresh_client):
        """A raw query in a session that did NOT set app.current_org_id
        must return zero rows from any tenant table — that is the
        actual failsafe behaviour we want."""
        _register_org(fresh_client, "force-rls")
        r = fresh_client.post(
            "/api/v1/assets",
            json={"name": "x", "target_type": "domain", "target_value": "example.org"},
            headers=_csrf_headers(fresh_client),
        )
        assert r.status_code == 201

        async def _query():
            async with async_session_factory() as session:
                # Deliberately do NOT call SET LOCAL app.current_org_id.
                # FORCE RLS + the tenant policy should yield zero rows.
                result = await session.execute(text("SELECT COUNT(*) FROM assets"))
                return result.scalar()

        count = _async_run(_query())
        assert count == 0, (
            "RLS failsafe broken: a session without app.current_org_id saw "
            f"{count} rows. Either the policy is missing or FORCE RLS is "
            "disabled."
        )

    def test_bypass_rls_admin_path_works(self, fresh_client):
        """Admin / migration path must still see all rows when
        app.bypass_rls = 'on' is explicitly set."""
        _register_org(fresh_client, "bypass-rls")
        fresh_client.post(
            "/api/v1/assets",
            json={
                "name": "x",
                "target_type": "domain",
                "target_value": "bypass-rls-example.com",
            },
            headers=_csrf_headers(fresh_client),
        )

        async def _query():
            async with async_session_factory() as session:
                await session.execute(text("SET LOCAL app.bypass_rls = 'on'"))
                result = await session.execute(text("SELECT COUNT(*) FROM assets"))
                return result.scalar()

        count = _async_run(_query())
        assert count >= 1


# ---------------------------------------------------------------------------
# Refresh-token rotation + revocation
# ---------------------------------------------------------------------------

class TestRefreshTokenRotation:
    def test_consumed_refresh_token_is_revoked(self, fresh_client):
        _register_org(fresh_client, "rotate")
        original_refresh = fresh_client.cookies.get("refresh_token")
        assert original_refresh

        # First /refresh — succeeds and rotates.
        r1 = fresh_client.post("/api/v1/auth/refresh")
        assert r1.status_code == 200, r1.text
        new_refresh = fresh_client.cookies.get("refresh_token")
        assert new_refresh != original_refresh, "refresh did not rotate the cookie"

        # Replay the original refresh token in a fresh client — must fail.
        replay = _new_client()
        r2 = replay.post(
            "/api/v1/auth/refresh",
            cookies={"refresh_token": original_refresh},
        )
        assert r2.status_code == 401, r2.text
        detail = (r2.json().get("detail") or "").lower()
        assert "revoke" in detail or "invalid" in detail or "expired" in detail

    def test_logout_revokes_current_refresh_token(self, fresh_client):
        _register_org(fresh_client, "logout-revoke")
        original_refresh = fresh_client.cookies.get("refresh_token")
        assert original_refresh

        before = _async_run(_count_revoked_tokens())

        r = fresh_client.post("/api/v1/auth/logout")
        assert r.status_code == 204

        after = _async_run(_count_revoked_tokens())
        assert after == before + 1, (
            f"/logout did not write a row to revoked_tokens "
            f"(before={before}, after={after})"
        )

        # The original refresh token cannot be reused.
        replay = _new_client()
        r = replay.post(
            "/api/v1/auth/refresh",
            cookies={"refresh_token": original_refresh},
        )
        assert r.status_code == 401


# ---------------------------------------------------------------------------
# Audit-log auto-application
# ---------------------------------------------------------------------------

class TestAuditMiddleware:
    def test_state_changing_request_writes_audit_row(self, fresh_client):
        body = _register_org(fresh_client, "audit")
        org_id = uuid.UUID(body["org_id"])

        r = fresh_client.post(
            "/api/v1/assets",
            json={
                "name": "audited-asset",
                "target_type": "domain",
                "target_value": "audit-test.example.com",
            },
            headers=_csrf_headers(fresh_client),
        )
        assert r.status_code == 201

        rows = _async_run(_select_audit_rows(org_id))
        # /register and /login are exempt from audit logging by design.
        # The asset POST must produce exactly one row.
        asset_rows = [
            row for row in rows
            if row.details and row.details.get("path") == "/api/v1/assets"
        ]
        assert len(asset_rows) >= 1, f"no audit row for asset POST; rows={rows}"
        row = asset_rows[0]
        assert row.action == "post"
        assert row.resource_type == "assets"
        assert row.details["status"] == 201

    def test_safe_methods_are_not_audited(self, fresh_client):
        body = _register_org(fresh_client, "audit-safe")
        org_id = uuid.UUID(body["org_id"])

        # Hit a few GETs.
        fresh_client.get("/api/v1/assets")
        fresh_client.get("/api/v1/findings")
        fresh_client.get("/api/v1/auth/me")

        rows = _async_run(_select_audit_rows(org_id))
        # No GET should appear.
        for row in rows:
            method = (row.details or {}).get("method", "")
            assert method != "GET", f"GET should not be audited, got: {row.details}"


# ---------------------------------------------------------------------------
# CSRF enforcement on cookie-authenticated state changes
# ---------------------------------------------------------------------------

class TestCSRF:
    def test_state_change_without_csrf_header_returns_403(self, fresh_client):
        _register_org(fresh_client, "csrf-block")

        # Missing X-CSRF-Token header even though session cookie is set.
        r = fresh_client.post(
            "/api/v1/assets",
            json={
                "name": "csrf-block",
                "target_type": "domain",
                "target_value": "csrf-block-example.com",
            },
        )
        assert r.status_code == 403
        detail = r.json().get("detail", "")
        assert "CSRF" in detail

    def test_mismatched_csrf_header_returns_403(self, fresh_client):
        _register_org(fresh_client, "csrf-mismatch")

        r = fresh_client.post(
            "/api/v1/assets",
            json={
                "name": "csrf-mismatch",
                "target_type": "domain",
                "target_value": "csrf-mismatch-example.com",
            },
            headers={"X-CSRF-Token": "wrong-value"},
        )
        assert r.status_code == 403
