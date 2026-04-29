# Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
v2.4.22 unit tests for `app.utils.report_dedup`.

Pins the dedup helper's behaviour against:

  - **Happy path**: a `register → lookup` round-trip returns the
    stored task_id; a `clear → lookup` round-trip returns None.
  - **Key isolation**: locks for different orgs / scans / formats
    don't collide. A cross-key lookup returns None.
  - **TTL**: the SET call passes the documented `INFLIGHT_TTL_SEC`.
    A regression that changes the value (or drops the EX flag,
    making the lock permanent) gets caught here.
  - **Failure tolerance**: when the underlying Redis client raises
    (connection refused, timeout, etc.), every helper logs and
    returns the "no lock present" / no-op answer rather than
    propagating the exception. This is the contract that lets the
    route keep working when Redis is briefly unavailable.

Tests use a tiny in-memory fake instead of `fakeredis` (one less
dep) — the surface we exercise is just `get` / `set` / `delete`,
and we want explicit control over which calls raise to test the
failure-tolerance branch.
"""
import pytest

from app.utils import report_dedup


class _FakeRedis:
    """Minimal in-memory stand-in for redis.Redis. Records calls
    to set so the TTL test can assert against the `ex` kwarg."""

    def __init__(self):
        self.store: dict[str, str] = {}
        self.set_calls: list[tuple[str, str, int | None]] = []

    def get(self, key: str):
        return self.store.get(key)

    def set(self, key: str, value: str, ex: int | None = None):
        self.store[key] = value
        self.set_calls.append((key, value, ex))

    def delete(self, key: str):
        self.store.pop(key, None)


class _RaisingRedis:
    """Redis stand-in where every method raises — simulates a
    network-level failure (connection refused / timeout)."""

    class _BoomError(Exception):
        pass

    # The helpers catch `redis.RedisError`; we use a subclass so
    # the test setup matches the real exception hierarchy without
    # needing a live Redis instance to import the type from.
    def get(self, key):
        import redis
        raise redis.RedisError("simulated connection refused")

    def set(self, key, value, ex=None):
        import redis
        raise redis.RedisError("simulated connection refused")

    def delete(self, key):
        import redis
        raise redis.RedisError("simulated connection refused")


@pytest.fixture
def fake_redis(monkeypatch):
    """Point the module at a fresh fake client. The fake is
    returned so individual tests can read .store / .set_calls."""
    fake = _FakeRedis()
    monkeypatch.setattr(report_dedup, "_client", fake)
    return fake


@pytest.fixture
def raising_redis(monkeypatch):
    monkeypatch.setattr(report_dedup, "_client", _RaisingRedis())


class TestRoundTrip:
    def test_register_then_lookup_returns_task_id(self, fake_redis):
        report_dedup.register_inflight_task("org1", "scan1", "pdf", "task-uuid-1")
        assert report_dedup.lookup_inflight_task("org1", "scan1", "pdf") == "task-uuid-1"

    def test_lookup_with_no_lock_returns_none(self, fake_redis):
        assert report_dedup.lookup_inflight_task("org1", "scan1", "pdf") is None

    def test_clear_drops_the_lock(self, fake_redis):
        report_dedup.register_inflight_task("org1", "scan1", "pdf", "task-uuid-1")
        report_dedup.clear_inflight_task("org1", "scan1", "pdf")
        assert report_dedup.lookup_inflight_task("org1", "scan1", "pdf") is None


class TestKeyIsolation:
    """Locks for different (org, scan, format) tuples must not
    collide. A regression that, say, used scan_id alone as the
    key would let two different orgs see each other's inflight
    state — a leak comparable to the v2.4.19 cross-tenant
    download bug."""

    def test_different_org_does_not_collide(self, fake_redis):
        report_dedup.register_inflight_task("org1", "scan1", "pdf", "task-A")
        assert report_dedup.lookup_inflight_task("org2", "scan1", "pdf") is None
        assert report_dedup.lookup_inflight_task("org1", "scan1", "pdf") == "task-A"

    def test_different_scan_does_not_collide(self, fake_redis):
        report_dedup.register_inflight_task("org1", "scan-A", "pdf", "task-A")
        report_dedup.register_inflight_task("org1", "scan-B", "pdf", "task-B")
        assert report_dedup.lookup_inflight_task("org1", "scan-A", "pdf") == "task-A"
        assert report_dedup.lookup_inflight_task("org1", "scan-B", "pdf") == "task-B"

    def test_different_format_does_not_collide(self, fake_redis):
        # Generating a PDF for a scan should NOT block the user
        # from also generating a CSV for the same scan
        # concurrently — different formats are independent jobs.
        report_dedup.register_inflight_task("org1", "scan1", "pdf", "task-pdf")
        report_dedup.register_inflight_task("org1", "scan1", "csv", "task-csv")
        assert report_dedup.lookup_inflight_task("org1", "scan1", "pdf") == "task-pdf"
        assert report_dedup.lookup_inflight_task("org1", "scan1", "csv") == "task-csv"


class TestTTL:
    """Pin the TTL so a refactor that drops the EX flag (which
    would make the lock permanent — never expires, blocks every
    future generation for that triple) gets caught here."""

    def test_register_passes_documented_ttl(self, fake_redis):
        report_dedup.register_inflight_task("org1", "scan1", "pdf", "task-1")
        assert len(fake_redis.set_calls) == 1
        key, value, ex = fake_redis.set_calls[0]
        assert ex == report_dedup.INFLIGHT_TTL_SEC
        assert ex == 300, (
            "INFLIGHT_TTL_SEC drift: a lock TTL longer than the "
            "FE poll timeout (5 min) makes legitimate retries "
            "wait; shorter risks the dedup window closing while "
            "the original task is still running."
        )


class TestFailureTolerance:
    """When Redis is unreachable, every helper must log and
    return the safe default. The route keeps working — the user
    gets a fresh task instead of being blocked."""

    def test_lookup_returns_none_on_redis_error(self, raising_redis, caplog):
        result = report_dedup.lookup_inflight_task("org1", "scan1", "pdf")
        assert result is None
        # Verify we logged something a sysadmin can grep for, but
        # don't pin the exact message (that would make refactors
        # painful for no reason).
        assert any("redis GET failed" in r.message for r in caplog.records), (
            "lookup_inflight_task should log a warning on Redis errors"
        )

    def test_register_swallows_redis_error(self, raising_redis):
        # Should NOT raise — the route relies on best-effort here.
        report_dedup.register_inflight_task("org1", "scan1", "pdf", "task-1")

    def test_clear_swallows_redis_error(self, raising_redis):
        # Same: postrun signal handlers in Celery shouldn't bring
        # down their containing task on a Redis blip.
        report_dedup.clear_inflight_task("org1", "scan1", "pdf")


class TestKeyShape:
    """The key prefix is part of the contract — it has to stay
    stable so a rolling deploy (v2.4.21 worker + v2.4.22 api, or
    the reverse) doesn't leave dangling locks under a different
    prefix that nobody clears."""

    def test_key_uses_documented_prefix(self):
        # Build a key indirectly via _key() to avoid coupling the
        # test to the exact string format. Just check the prefix.
        key = report_dedup._key("org1", "scan1", "pdf")
        assert key.startswith("reports:inflight:")
        assert "org1" in key
        assert "scan1" in key
        assert "pdf" in key
