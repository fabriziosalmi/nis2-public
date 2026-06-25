# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
"""M3: per-account login lockout. Pure-logic + fake-Redis — no server needed."""
import asyncio

import pytest

from app.utils import login_throttle


class FakeRedis:
    """Minimal async Redis stand-in covering the ops login_throttle uses."""

    def __init__(self):
        self.vals: dict[str, object] = {}
        self.ttls: dict[str, int] = {}

    async def incr(self, key):
        self.vals[key] = int(self.vals.get(key, 0)) + 1
        return self.vals[key]

    async def expire(self, key, seconds):
        self.ttls[key] = seconds
        return True

    async def set(self, key, value, ex=None):
        self.vals[key] = value
        if ex is not None:
            self.ttls[key] = ex
        return True

    async def ttl(self, key):
        if key not in self.vals and key not in self.ttls:
            return -2  # redis convention: key does not exist
        return self.ttls.get(key, -1)

    async def delete(self, *keys):
        n = 0
        for k in keys:
            if k in self.vals:
                del self.vals[k]
                n += 1
            self.ttls.pop(k, None)
        return n


@pytest.fixture(autouse=True)
def fake_redis(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(login_throttle, "_redis", fake)
    return fake


def test_lock_duration_progression():
    assert login_throttle.lock_duration(0) == 0
    assert login_throttle.lock_duration(1) == login_throttle.BASE_LOCK_SECONDS
    assert login_throttle.lock_duration(2) == login_throttle.BASE_LOCK_SECONDS * 2
    assert login_throttle.lock_duration(3) == login_throttle.BASE_LOCK_SECONDS * 4
    # capped
    assert login_throttle.lock_duration(99) == login_throttle.MAX_LOCK_SECONDS


def test_not_locked_initially():
    assert asyncio.run(login_throttle.seconds_until_unlock("a@b.com")) == 0


def test_locks_after_threshold():
    async def scenario():
        email = "victim@example.com"
        for _ in range(login_throttle.MAX_FAILED_ATTEMPTS - 1):
            assert await login_throttle.record_failure(email) == 0
        assert await login_throttle.seconds_until_unlock(email) == 0
        # the threshold failure locks the account
        assert (
            await login_throttle.record_failure(email)
            == login_throttle.BASE_LOCK_SECONDS
        )
        assert (
            await login_throttle.seconds_until_unlock(email)
            == login_throttle.BASE_LOCK_SECONDS
        )

    asyncio.run(scenario())


def test_repeat_lockout_escalates():
    async def scenario():
        email = "repeat@example.com"
        for _ in range(login_throttle.MAX_FAILED_ATTEMPTS):
            await login_throttle.record_failure(email)
        await login_throttle.reset(email)  # window cleared but lockcount persists
        # second lockout cycle must be longer (progressive backoff)
        last = 0
        for _ in range(login_throttle.MAX_FAILED_ATTEMPTS):
            last = await login_throttle.record_failure(email)
        assert last == login_throttle.BASE_LOCK_SECONDS * 2

    asyncio.run(scenario())


def test_reset_clears_lock():
    async def scenario():
        email = "u@example.com"
        for _ in range(login_throttle.MAX_FAILED_ATTEMPTS):
            await login_throttle.record_failure(email)
        assert await login_throttle.seconds_until_unlock(email) > 0
        await login_throttle.reset(email)
        assert await login_throttle.seconds_until_unlock(email) == 0

    asyncio.run(scenario())


def test_email_normalized():
    async def scenario():
        for _ in range(login_throttle.MAX_FAILED_ATTEMPTS):
            await login_throttle.record_failure("Victim@Example.COM")
        # a differently-cased / padded form maps to the same locked account
        assert await login_throttle.seconds_until_unlock("  victim@example.com ") > 0

    asyncio.run(scenario())


def test_fails_open_when_redis_unavailable(monkeypatch):
    class BrokenRedis:
        async def incr(self, *a):
            raise RuntimeError("redis down")

        async def ttl(self, *a):
            raise RuntimeError("redis down")

        async def expire(self, *a):
            raise RuntimeError("redis down")

        async def set(self, *a, **k):
            raise RuntimeError("redis down")

        async def delete(self, *a):
            raise RuntimeError("redis down")

    monkeypatch.setattr(login_throttle, "_redis", BrokenRedis())
    # Every entry point must fail open (no exception, never locks).
    assert asyncio.run(login_throttle.seconds_until_unlock("x@y.com")) == 0
    assert asyncio.run(login_throttle.record_failure("x@y.com")) == 0
    asyncio.run(login_throttle.reset("x@y.com"))  # must not raise
