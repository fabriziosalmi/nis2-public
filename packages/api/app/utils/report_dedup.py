# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
v2.4.22 audit reports-009 — in-flight deduplication for `POST /api/v1/reports/generate`.

Without this, a user clicking "Generate" twice rapidly (or a script
opening 100 tabs and clicking each) queues two separate Celery
tasks for the same `(org_id, scan_id, format)` triple. Both run
to completion, both write a file to `/tmp/nis2-reports/`, the
later one overwrites the earlier in UI state — but the disk now
holds two copies of effectively the same report.

The v2.4.19 5/min/IP rate limit prevents the most egregious
abuse, but a curious power user (or an automation script that
isn't malicious — just zealous) can still create 5 dupes per
minute per IP.

This module backs the dedup with **a Redis lock keyed on
`(org_id, scan_id, format)`**. The flow:

  1. POST `/generate` arrives.
  2. The route calls `lookup_inflight_task()`. If a task_id is
     stored under the key, return that → user gets the same task
     they queued seconds ago.
  3. Otherwise the route calls `Celery.delay()` to mint a fresh
     task, then calls `register_inflight_task()` to store the new
     task_id with a 300-second TTL.
  4. When the Celery task finishes (success OR failure), a
     `task_postrun` signal handler in `report_tasks.py` calls
     `clear_inflight_task()` so a follow-up legitimate
     regeneration isn't blocked for the full TTL.

**Why Redis (not the DB)**:
- Redis is already in the stack as Celery's broker + result
  backend; no new dependency.
- TTL is native (`SET ... EX ...`), so a task that genuinely
  hangs / disappears doesn't permanently block its slot — the key
  expires within 5 min.
- Sub-millisecond round-trip; the lock check adds no perceptible
  latency to `/generate`.

**Failure mode**: if Redis is unreachable (network blip,
cluster failover), every helper here logs and returns the
"no lock present" answer. The caller proceeds to mint a fresh
task. Result: temporary loss of dedup, but never a blocked
report generation. This is the safest possible failure mode —
the alternative (refusing to generate when Redis is down) would
be a worse user experience for what is itself a polish feature.
"""
from __future__ import annotations

import logging
from typing import Optional

import redis

from app.config import settings

logger = logging.getLogger(__name__)

# 5 minutes. Matches the FE's POLL_TIMEOUT_MS — by the time the
# FE gives up polling, the lock has expired and a fresh request
# can mint a new task. Setting it shorter risks racing the
# Celery task; setting it longer risks blocking legitimate
# retries after a failed task (the postrun signal clears it
# proactively, but if THAT also fails we don't want the user
# stuck).
INFLIGHT_TTL_SEC = 300

# Redis db routing: we reuse the celery_result_backend URL (db=2
# in dev). Putting lock keys in the result-backend db keeps them
# logically grouped with the Celery task results they're guarding,
# and avoids needing a new env var. Lock keys are namespaced via
# `reports:inflight:` so they can't collide with Celery's own
# `celery-task-meta-*` / `_kombu.binding.*` keys.
_KEY_PREFIX = "reports:inflight"

# Org-level concurrency set: `reports:org_inflight:{org_id}` is a Redis
# Set whose members are the task_ids currently in flight for that org.
# SCARD gives the count; SADD/SREM maintain membership. TTL is refreshed
# on every SADD so stale entries from crashed workers self-heal within
# INFLIGHT_TTL_SEC. This is a separate namespace from the per-(org,scan,fmt)
# dedup keys above — both are cleared by `clear_inflight_task`.
_ORG_SET_PREFIX = "reports:org_inflight"

# Lazy-initialised module-level client. The client is thread-safe
# (per redis-py docs) so reusing it across requests is fine.
_client: Optional[redis.Redis] = None


def _get_client() -> Optional[redis.Redis]:
    """Return a Redis client, or None if the connection setup
    fails. The route handlers use the None case as the "no lock,
    proceed normally" signal — the alternative (raise on failure)
    would couple report generation to Redis availability and
    that's the wrong tradeoff for a polish feature."""
    global _client
    if _client is not None:
        return _client
    try:
        # `decode_responses=True` so .get() returns str (we store
        # the task UUID as a UTF-8 string). Cleaner than peppering
        # `.decode()` calls at every call site.
        _client = redis.from_url(
            settings.celery_result_backend,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
    except Exception as exc:
        logger.warning("report-dedup: redis client init failed: %s", exc)
        _client = None
    return _client


def _org_set_key(org_id: str) -> str:
    return f"{_ORG_SET_PREFIX}:{org_id}"


def _key(org_id: str, scan_id: str, fmt: str) -> str:
    """Compose the lock key. Org_id is included even though
    scan_id alone is unique — defense-in-depth so a future
    `share scan across orgs` refactor doesn't accidentally let
    one org's dedup state leak into another's."""
    return f"{_KEY_PREFIX}:{org_id}:{scan_id}:{fmt}"


def count_inflight_per_org(org_id: str) -> int:
    """Return the number of report tasks currently in flight for *org_id*.

    Uses SCARD on the org-level Set. Returns 0 on Redis failure so the
    caller never blocks legitimate requests because of a Redis blip.
    """
    client = _get_client()
    if client is None:
        return 0
    try:
        return client.scard(_org_set_key(org_id)) or 0
    except redis.RedisError as exc:
        logger.warning(
            "report-dedup: redis SCARD failed for org %s: %s", org_id, exc
        )
        return 0


def lookup_inflight_task(org_id: str, scan_id: str, fmt: str) -> Optional[str]:
    """Return the task_id of an in-flight report generation for
    this `(org_id, scan_id, fmt)` triple, or None if no lock is
    held. None on Redis failure — see module docstring for
    rationale."""
    client = _get_client()
    if client is None:
        return None
    try:
        return client.get(_key(org_id, scan_id, fmt))
    except redis.RedisError as exc:
        logger.warning(
            "report-dedup: redis GET failed for (%s, %s, %s): %s",
            org_id, scan_id, fmt, exc,
        )
        return None


def register_inflight_task(
    org_id: str, scan_id: str, fmt: str, task_id: str
) -> None:
    """Store the task_id under the lock key with TTL and add it to the
    org-level concurrency Set. Both are best-effort — failure is logged,
    not raised. The org Set TTL is refreshed on every SADD so stale
    entries from crashed workers self-heal within INFLIGHT_TTL_SEC."""
    client = _get_client()
    if client is None:
        return
    try:
        client.set(_key(org_id, scan_id, fmt), task_id, ex=INFLIGHT_TTL_SEC)
        org_key = _org_set_key(org_id)
        client.sadd(org_key, task_id)
        client.expire(org_key, INFLIGHT_TTL_SEC)
    except redis.RedisError as exc:
        logger.warning(
            "report-dedup: redis SET/SADD failed for (%s, %s, %s): %s",
            org_id, scan_id, fmt, exc,
        )


def clear_inflight_task(org_id: str, scan_id: str, fmt: str, task_id: str | None = None) -> None:
    """Drop the lock for a `(org_id, scan_id, fmt)` triple and remove
    *task_id* from the org-level concurrency Set (if provided).

    Called from a Celery `task_postrun` signal handler when the report
    generation finishes (success or failure). Best-effort: a failure here
    is acceptable because TTL eventually evicts both the lock key and the
    org Set.
    """
    client = _get_client()
    if client is None:
        return
    try:
        client.delete(_key(org_id, scan_id, fmt))
        if task_id:
            client.srem(_org_set_key(org_id), task_id)
    except redis.RedisError as exc:
        logger.warning(
            "report-dedup: redis DEL/SREM failed for (%s, %s, %s): %s",
            org_id, scan_id, fmt, exc,
        )
