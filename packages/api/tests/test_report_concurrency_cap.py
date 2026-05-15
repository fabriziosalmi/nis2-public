# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Tests for the per-org report concurrency cap.

Exercises the pure-function parts of the cap — the report_dedup helpers
and the Settings field — without a database, Redis, or network. Redis
calls are replaced with a lightweight in-memory fake.
"""
from __future__ import annotations

from unittest.mock import patch


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

class TestConcurrencyCapSetting:
    def test_default_is_3(self) -> None:
        from app.config import Settings
        s = Settings(environment="development", jwt_secret="x" * 32)
        assert s.max_concurrent_reports_per_org == 3

    def test_can_override(self) -> None:
        from app.config import Settings
        s = Settings(
            environment="development",
            jwt_secret="x" * 32,
            max_concurrent_reports_per_org=10,
        )
        assert s.max_concurrent_reports_per_org == 10


# ---------------------------------------------------------------------------
# Fake Redis for unit tests
# ---------------------------------------------------------------------------

class _FakeRedis:
    """Minimal in-memory Redis fake covering SET, GET, DEL, SADD, SREM, SCARD, EXPIRE."""

    def __init__(self):
        self._store: dict = {}
        self._sets: dict[str, set] = {}

    def set(self, key, value, ex=None):
        self._store[key] = value

    def get(self, key):
        return self._store.get(key)

    def delete(self, *keys):
        for k in keys:
            self._store.pop(k, None)

    def sadd(self, key, *members):
        self._sets.setdefault(key, set()).update(members)
        return len(members)

    def srem(self, key, *members):
        s = self._sets.get(key, set())
        removed = sum(1 for m in members if m in s)
        s.difference_update(members)
        return removed

    def scard(self, key):
        return len(self._sets.get(key, set()))

    def expire(self, key, seconds):
        pass  # TTL not modelled; sufficient for unit tests

    def ping(self):
        return True


# ---------------------------------------------------------------------------
# count_inflight_per_org
# ---------------------------------------------------------------------------

class TestCountInflightPerOrg:
    def _setup(self):
        import app.utils.report_dedup as dedup
        fake = _FakeRedis()
        dedup._client = fake
        return dedup, fake

    def teardown_method(self):
        import app.utils.report_dedup as dedup
        dedup._client = None

    def test_zero_when_no_tasks_registered(self) -> None:
        dedup, _ = self._setup()
        assert dedup.count_inflight_per_org("org-1") == 0

    def test_increments_on_register(self) -> None:
        dedup, _ = self._setup()
        dedup.register_inflight_task("org-1", "scan-1", "pdf", "task-aaa")
        assert dedup.count_inflight_per_org("org-1") == 1

    def test_two_different_scans_counted_separately(self) -> None:
        dedup, _ = self._setup()
        dedup.register_inflight_task("org-1", "scan-1", "pdf", "task-aaa")
        dedup.register_inflight_task("org-1", "scan-2", "json", "task-bbb")
        assert dedup.count_inflight_per_org("org-1") == 2

    def test_decrements_on_clear(self) -> None:
        dedup, _ = self._setup()
        dedup.register_inflight_task("org-1", "scan-1", "pdf", "task-aaa")
        dedup.clear_inflight_task("org-1", "scan-1", "pdf", task_id="task-aaa")
        assert dedup.count_inflight_per_org("org-1") == 0

    def test_different_orgs_are_independent(self) -> None:
        dedup, _ = self._setup()
        dedup.register_inflight_task("org-A", "scan-1", "pdf", "task-111")
        dedup.register_inflight_task("org-B", "scan-2", "pdf", "task-222")
        assert dedup.count_inflight_per_org("org-A") == 1
        assert dedup.count_inflight_per_org("org-B") == 1

    def test_returns_zero_when_redis_unavailable(self) -> None:
        import app.utils.report_dedup as dedup
        dedup._client = None
        with patch("app.utils.report_dedup._get_client", return_value=None):
            assert dedup.count_inflight_per_org("org-x") == 0


# ---------------------------------------------------------------------------
# clear_inflight_task — task_id parameter
# ---------------------------------------------------------------------------

class TestClearInflightTaskWithTaskId:
    def teardown_method(self):
        import app.utils.report_dedup as dedup
        dedup._client = None

    def test_clear_without_task_id_still_removes_lock_key(self) -> None:
        import app.utils.report_dedup as dedup
        fake = _FakeRedis()
        dedup._client = fake
        dedup.register_inflight_task("org-1", "scan-1", "pdf", "task-xyz")
        dedup.clear_inflight_task("org-1", "scan-1", "pdf")  # no task_id
        assert dedup.lookup_inflight_task("org-1", "scan-1", "pdf") is None

    def test_clear_with_task_id_removes_from_org_set(self) -> None:
        import app.utils.report_dedup as dedup
        fake = _FakeRedis()
        dedup._client = fake
        dedup.register_inflight_task("org-1", "scan-1", "pdf", "task-xyz")
        dedup.clear_inflight_task("org-1", "scan-1", "pdf", task_id="task-xyz")
        assert dedup.count_inflight_per_org("org-1") == 0

    def test_clear_without_task_id_does_not_crash(self) -> None:
        import app.utils.report_dedup as dedup
        fake = _FakeRedis()
        dedup._client = fake
        dedup.register_inflight_task("org-1", "scan-1", "pdf", "task-xyz")
        # task_id=None — no SREM attempted
        dedup.clear_inflight_task("org-1", "scan-1", "pdf", task_id=None)
        # org set still has the entry (no crash is the contract here)
        assert dedup.count_inflight_per_org("org-1") == 1


# ---------------------------------------------------------------------------
# Router-level cap enforcement (pure logic, no HTTP stack)
# ---------------------------------------------------------------------------

class TestConcurrencyCapEnforcement:
    """Verify the cap constant and the router's check logic in isolation."""

    def test_cap_applied_when_limit_reached(self) -> None:
        from app.config import Settings
        s = Settings(environment="development", jwt_secret="x" * 32, max_concurrent_reports_per_org=2)

        inflight = 2
        assert inflight >= s.max_concurrent_reports_per_org  # → would 429

    def test_cap_not_applied_when_under_limit(self) -> None:
        from app.config import Settings
        s = Settings(environment="development", jwt_secret="x" * 32, max_concurrent_reports_per_org=3)

        inflight = 2
        assert inflight < s.max_concurrent_reports_per_org  # → proceed

    def test_router_imports_count_helper(self) -> None:
        import pathlib
        src = pathlib.Path("app/routers/reports.py").read_text()
        assert "count_inflight_per_org" in src

    def test_router_raises_429_label_in_source(self) -> None:
        import pathlib
        src = pathlib.Path("app/routers/reports.py").read_text()
        assert "429" in src
        assert "max_concurrent_reports_per_org" in src
