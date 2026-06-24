# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
v2.4.26 unit tests for the API-key scope validator.

The validator lives in `app.routers.api_keys._validate_scopes`. Pre-2.4.26
the create endpoint accepted any list of strings as scopes — including
empty strings, unknown verbs, and duplicates — and persisted them. The
UI then implied enforcement that didn't exist.

These tests pin the canonical vocabulary at the point where it's
checked. Route-level enforcement of the scopes (refusing a `scan:write`
call from a key with only `scan:read`) is a separate, larger
behavioural change tracked for a follow-up patch.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.routers.api_keys import VALID_API_KEY_SCOPES, _validate_scopes


class TestValidScopes:
    def test_default_set_passes(self) -> None:
        # The default in ApiKeyCreate.Field; if this ever drifts away
        # from the vocabulary, this test fails before users do.
        assert _validate_scopes(["scan:read", "scan:write", "report:read"]) == [
            "scan:read",
            "scan:write",
            "report:read",
        ]

    def test_single_scope(self) -> None:
        assert _validate_scopes(["scan:read"]) == ["scan:read"]

    def test_all_scopes(self) -> None:
        # Pass the whole vocabulary in (sorted to keep the test stable).
        sorted_all = sorted(VALID_API_KEY_SCOPES)
        assert _validate_scopes(sorted_all) == sorted_all

    def test_whitespace_trimmed(self) -> None:
        # The cleaner strips surrounding whitespace so a copy-paste
        # from a UI text field with stray spaces still works.
        assert _validate_scopes(["  scan:read  "]) == ["scan:read"]

    def test_none_passes_through(self) -> None:
        # None means "no scopes field on the request" — the schema
        # default is applied elsewhere; the validator should not
        # over-reach and reject None.
        assert _validate_scopes(None) is None


class TestInvalidScopes:
    def test_rejects_unknown_scope(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            _validate_scopes(["yolo:read"])
        assert exc_info.value.status_code == 400
        assert "unknown scope" in exc_info.value.detail.lower()
        # The error message lists the allowed scopes so the UI can
        # show a hint without an extra round-trip.
        assert "scan:read" in exc_info.value.detail

    def test_rejects_typo_in_known_scope(self) -> None:
        # `scan:reads` (extra s) used to silently work pre-2.4.26.
        with pytest.raises(HTTPException) as exc_info:
            _validate_scopes(["scan:reads"])
        assert exc_info.value.status_code == 400

    def test_rejects_empty_string(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            _validate_scopes([""])
        assert exc_info.value.status_code == 400
        assert "empty" in exc_info.value.detail.lower()

    def test_rejects_whitespace_only(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            _validate_scopes(["   "])
        assert exc_info.value.status_code == 400

    def test_rejects_empty_list(self) -> None:
        # Distinct from None: explicit empty list is user error.
        with pytest.raises(HTTPException) as exc_info:
            _validate_scopes([])
        assert exc_info.value.status_code == 400
        assert "empty" in exc_info.value.detail.lower()

    def test_rejects_duplicate(self) -> None:
        # Duplicates are almost certainly UI bugs / copy-paste; we
        # surface them rather than silently dedupe.
        with pytest.raises(HTTPException) as exc_info:
            _validate_scopes(["scan:read", "scan:read"])
        assert exc_info.value.status_code == 400
        assert "duplicate" in exc_info.value.detail.lower()

    def test_rejects_non_list(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            _validate_scopes("scan:read")  # type: ignore[arg-type]
        assert exc_info.value.status_code == 400

    def test_rejects_non_string_element(self) -> None:
        with pytest.raises(HTTPException) as exc_info:
            _validate_scopes(["scan:read", 42])  # type: ignore[list-item]
        assert exc_info.value.status_code == 400


class TestScopeEnforcement:
    """Pin the runtime enforcement logic in _resolve_dual_auth.

    These tests exercise the scope-check branch directly, without
    standing up a full FastAPI app or hitting a database. We build
    the minimum objects needed (an ApiKey with a known scope list)
    and call _resolve_dual_auth with a mocked DB and request.
    """

    def _make_api_key(self, scopes: list[str] | None):
        from unittest.mock import MagicMock
        import uuid as _uuid

        key = MagicMock()
        key.scopes = scopes
        key.organization_id = _uuid.uuid4()
        key.is_active = True
        key.expires_at = None
        return key

    def _make_request(self, has_cookie: bool = False):
        from unittest.mock import MagicMock

        req = MagicMock()
        req.cookies.get = MagicMock(return_value="tok" if has_cookie else None)
        req.state = MagicMock()
        return req

    @pytest.mark.asyncio
    async def test_matching_scope_allowed(self) -> None:
        """API key with required scope must pass."""
        from unittest.mock import AsyncMock, MagicMock, patch

        api_key = self._make_api_key(["scan:read", "report:read"])
        org_id = api_key.organization_id

        creds = MagicMock()
        creds.credentials = "nis2_fakekey"

        req = self._make_request(has_cookie=False)
        db = AsyncMock()

        with patch(
            "app.dependencies.get_api_key_org",
            new=AsyncMock(return_value=(api_key, org_id)),
        ):
            from app.dependencies import _resolve_dual_auth

            result = await _resolve_dual_auth(req, creds, db, required_scope="scan:read")

        assert result == org_id

    @pytest.mark.asyncio
    async def test_missing_scope_raises_403(self) -> None:
        """API key without required scope must be rejected."""
        from unittest.mock import AsyncMock, MagicMock, patch
        from fastapi import HTTPException

        api_key = self._make_api_key(["report:read"])
        org_id = api_key.organization_id

        creds = MagicMock()
        creds.credentials = "nis2_fakekey"

        req = self._make_request(has_cookie=False)
        db = AsyncMock()

        with patch(
            "app.dependencies.get_api_key_org",
            new=AsyncMock(return_value=(api_key, org_id)),
        ):
            from app.dependencies import _resolve_dual_auth

            with pytest.raises(HTTPException) as exc_info:
                await _resolve_dual_auth(req, creds, db, required_scope="scan:read")

        assert exc_info.value.status_code == 403
        assert "scan:read" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_legacy_key_with_none_scopes_fails(self) -> None:
        """Legacy API keys (scopes=None, pre-2.4.26) are treated as empty list and fail."""
        from unittest.mock import AsyncMock, MagicMock, patch
        from fastapi import HTTPException

        api_key = self._make_api_key(None)
        org_id = api_key.organization_id

        creds = MagicMock()
        creds.credentials = "nis2_fakekey"

        req = self._make_request(has_cookie=False)
        db = AsyncMock()

        with patch(
            "app.dependencies.get_api_key_org",
            new=AsyncMock(return_value=(api_key, org_id)),
        ):
            from app.dependencies import _resolve_dual_auth

            with pytest.raises(HTTPException) as exc_info:
                await _resolve_dual_auth(req, creds, db, required_scope="scan:read")

        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_cookie_session_bypasses_scope_check(self) -> None:
        """JWT cookie sessions are never scope-checked; they go through the JWT path."""
        from unittest.mock import AsyncMock, MagicMock, patch
        import uuid as _uuid

        org_id = _uuid.uuid4()
        user = MagicMock()
        membership = MagicMock()
        membership.organization_id = org_id

        creds = MagicMock()
        creds.credentials = "jwt.token.here"

        req = self._make_request(has_cookie=True)
        db = AsyncMock()

        with (
            patch("app.dependencies.get_current_user", new=AsyncMock(return_value=user)),
            patch(
                "app.dependencies.get_current_org",
                new=AsyncMock(return_value=(user, membership)),
            ),
        ):
            from app.dependencies import _resolve_dual_auth

            result = await _resolve_dual_auth(req, creds, db, required_scope="scan:read")

        assert result == org_id


class TestVocabularyShape:
    """Pin the vocabulary itself so adding a scope is a deliberate
    one-line change to api_keys.py PLUS this test, never an accident."""

    def test_vocabulary_is_immutable(self) -> None:
        assert isinstance(VALID_API_KEY_SCOPES, frozenset)

    def test_every_scope_has_resource_and_verb(self) -> None:
        # Shape: <resource>:<verb>. Verb must be `read` or `write`.
        for scope in VALID_API_KEY_SCOPES:
            assert ":" in scope, f"scope {scope!r} missing colon"
            resource, verb = scope.split(":", 1)
            assert resource, f"scope {scope!r} has empty resource"
            assert verb in {"read", "write"}, f"scope {scope!r} has bad verb"
