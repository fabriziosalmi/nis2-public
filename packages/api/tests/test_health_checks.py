# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Tests for the /health/* endpoints (pure-logic layer, no live deps).

Verifies the three-tier health model:
  - GET /health  (liveness) — always 200
  - GET /health/live — alias for liveness
  - GET /health/ready — readiness: DB + Redis + Celery

Celery/Redis/DB calls are replaced with unittest mocks so the suite runs
without infrastructure.
"""
from __future__ import annotations

import pathlib


# ---------------------------------------------------------------------------
# Source-level contract tests (no HTTP stack needed)
# ---------------------------------------------------------------------------

class TestHealthSourceContracts:
    def _src(self) -> str:
        return pathlib.Path("app/routers/health.py").read_text()

    def test_liveness_endpoint_exists(self) -> None:
        assert '@router.get("")' in self._src() or "def health" in self._src()

    def test_live_alias_exists(self) -> None:
        assert '"/live"' in self._src()

    def test_ready_endpoint_exists(self) -> None:
        assert '"/ready"' in self._src()

    def test_database_check_present(self) -> None:
        assert "SELECT 1" in self._src()

    def test_redis_check_present(self) -> None:
        assert "redis" in self._src().lower()
        assert "ping" in self._src()

    def test_celery_check_present(self) -> None:
        assert "celery" in self._src().lower()
        assert "inspect" in self._src()

    def test_503_returned_on_error(self) -> None:
        assert "503" in self._src()

    def test_degraded_status_string_present(self) -> None:
        assert '"degraded"' in self._src()

    def test_celery_timeout_is_short(self) -> None:
        # We want a tight timeout so a hung worker pool doesn't stall probes.
        src = self._src()
        # Extract _CELERY_PING_TIMEOUT value and verify it's ≤ 10 s.
        import re
        m = re.search(r"_CELERY_PING_TIMEOUT\s*=\s*(\d+)", src)
        assert m, "_CELERY_PING_TIMEOUT constant not found"
        assert int(m.group(1)) <= 10, "Celery ping timeout should be ≤ 10 s"


# ---------------------------------------------------------------------------
# Unit tests for the readiness logic using direct function calls
# ---------------------------------------------------------------------------

from unittest.mock import AsyncMock, MagicMock, patch


class TestReadinessLogic:
    """Call the route handler function directly with mocked deps."""

    async def _call_ready(self, db_ok: bool, redis_ok: bool, celery_workers: int):
        from fastapi import Response
        from app.routers.health import readiness

        # Mock DB session
        db = AsyncMock()
        if not db_ok:
            db.execute.side_effect = Exception("DB down")

        # Patch redis and celery at the module level used by health.py
        response = Response()

        with patch("app.routers.health.settings") as mock_settings, \
             patch("redis.asyncio.from_url") as mock_redis_cls, \
             patch("app.tasks.celery_app.celery_app") as mock_celery_app:

            mock_settings.redis_url = "redis://localhost:6379/0"

            redis_instance = AsyncMock()
            if not redis_ok:
                redis_instance.ping.side_effect = Exception("Redis down")
            mock_redis_cls.return_value = redis_instance

            inspector = MagicMock()
            if celery_workers > 0:
                inspector.ping.return_value = {f"worker{i}": {"ok": "pong"} for i in range(celery_workers)}
            else:
                inspector.ping.return_value = {}
            mock_celery_app.control.inspect.return_value = inspector

            result = await readiness(response=response, db=db)
            return result, response.status_code

    def test_all_ok_returns_200_and_ok_status(self) -> None:
        import asyncio
        result, status = asyncio.get_event_loop().run_until_complete(
            self._call_ready(db_ok=True, redis_ok=True, celery_workers=1)
        )
        assert result["status"] == "ok"
        assert status != 503

    def test_db_error_returns_503(self) -> None:
        import asyncio
        result, status = asyncio.get_event_loop().run_until_complete(
            self._call_ready(db_ok=False, redis_ok=True, celery_workers=1)
        )
        assert result["status"] == "degraded"
        assert status == 503

    def test_redis_error_returns_503(self) -> None:
        import asyncio
        result, status = asyncio.get_event_loop().run_until_complete(
            self._call_ready(db_ok=True, redis_ok=False, celery_workers=1)
        )
        assert result["status"] == "degraded"
        assert status == 503

    def test_no_celery_workers_is_degraded_not_error(self) -> None:
        import asyncio
        result, status = asyncio.get_event_loop().run_until_complete(
            self._call_ready(db_ok=True, redis_ok=True, celery_workers=0)
        )
        # No workers → degraded, but NOT a hard 503 (workers may be idle)
        assert result["checks"]["celery_workers"] == "degraded"
        assert status != 503

    def test_checks_dict_has_all_three_keys(self) -> None:
        import asyncio
        result, _ = asyncio.get_event_loop().run_until_complete(
            self._call_ready(db_ok=True, redis_ok=True, celery_workers=1)
        )
        assert "database" in result["checks"]
        assert "redis" in result["checks"]
        assert "celery_workers" in result["checks"]
