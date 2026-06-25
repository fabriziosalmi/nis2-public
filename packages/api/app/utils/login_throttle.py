# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""Per-account login throttling with progressive lockout (M3 hardening).

The per-IP slowapi limit on /auth/login is easily diluted across many source
IPs and, behind a reverse proxy, can collapse to the proxy's own IP. This module
adds an IP-independent defense: failed attempts are counted per email in Redis,
and after MAX_FAILED_ATTEMPTS within FAIL_WINDOW_SECONDS the account is locked
for a progressively longer duration.

Fails OPEN if Redis is unreachable — a Redis outage must never lock every user
out of the platform (availability > strict throttling for this control).

Tradeoff: an attacker who knows an email can deliberately trip the lockout to
deny that user service. The lockout is bounded (progressive, capped at 1 h) and
auto-expires, which is the standard accepted tradeoff for brute-force defense.
"""
from __future__ import annotations

import logging

from app.config import settings

logger = logging.getLogger(__name__)

MAX_FAILED_ATTEMPTS = 5
FAIL_WINDOW_SECONDS = 900  # rolling window to accumulate failures (15 min)
BASE_LOCK_SECONDS = 60  # first lockout duration
MAX_LOCK_SECONDS = 3600  # cap a single lockout at 1 h

_FAIL_KEY = "login:fail:{email}"
_LOCK_KEY = "login:lock:{email}"
_LOCKCOUNT_KEY = "login:lockcount:{email}"

_redis = None


def lock_duration(consecutive_lockouts: int) -> int:
    """Progressive backoff: BASE * 2^(n-1), capped at MAX. Pure → unit-testable."""
    if consecutive_lockouts < 1:
        return 0
    return min(BASE_LOCK_SECONDS * 2 ** (consecutive_lockouts - 1), MAX_LOCK_SECONDS)


async def _client():
    """Lazily create a per-process async Redis client. One event loop per
    gunicorn worker, so a module-level client is safe here (unlike Celery,
    which mints a fresh loop per task)."""
    global _redis
    if _redis is None:
        import redis.asyncio as aioredis

        # Short timeouts bound the fail-open latency added to the login path
        # when Redis is unreachable (~2s instead of a long default).
        _redis = aioredis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
    return _redis


def _norm(email: str) -> str:
    return (email or "").strip().lower()


async def seconds_until_unlock(email: str) -> int:
    """Remaining lock time for this account (0 if not locked). Fail-open."""
    try:
        ttl = await (await _client()).ttl(_LOCK_KEY.format(email=_norm(email)))
        return ttl if ttl and ttl > 0 else 0
    except Exception as exc:  # noqa: BLE001
        logger.warning("login_throttle: Redis unavailable (lock check): %s", exc)
        return 0


async def record_failure(email: str) -> int:
    """Count a failed attempt and lock the account when the threshold is crossed.

    Returns the lock duration just applied (0 if not yet locked). Fail-open.
    """
    e = _norm(email)
    try:
        r = await _client()
        fails = await r.incr(_FAIL_KEY.format(email=e))
        if fails == 1:
            await r.expire(_FAIL_KEY.format(email=e), FAIL_WINDOW_SECONDS)
        if fails >= MAX_FAILED_ATTEMPTS:
            lockcount = await r.incr(_LOCKCOUNT_KEY.format(email=e))
            await r.expire(_LOCKCOUNT_KEY.format(email=e), MAX_LOCK_SECONDS * 4)
            duration = lock_duration(lockcount)
            await r.set(_LOCK_KEY.format(email=e), "1", ex=duration)
            await r.delete(_FAIL_KEY.format(email=e))  # reset the window post-lock
            logger.warning(
                "login_throttle: account locked email=%s for %ds (lockout #%d)",
                e,
                duration,
                lockcount,
            )
            return duration
        return 0
    except Exception as exc:  # noqa: BLE001
        logger.warning("login_throttle: Redis unavailable (record failure): %s", exc)
        return 0


async def reset(email: str) -> None:
    """Clear failure/lock state after a successful login. Fail-open."""
    e = _norm(email)
    try:
        r = await _client()
        # Clear the failure window and any active lock so the user can proceed.
        # Deliberately KEEP the lockcount (escalation memory, TTL-bounded) so a
        # lock -> unlock -> re-lock attack escalates instead of resetting to BASE.
        await r.delete(
            _FAIL_KEY.format(email=e),
            _LOCK_KEY.format(email=e),
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("login_throttle: Redis unavailable (reset): %s", exc)
