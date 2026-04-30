# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""Periodic cleanup of expired auth-side records.

v2.5.1: pre-2.5.1 the `revoked_tokens` and `password_reset_tokens`
tables had model-level documentation saying "a periodic Celery task
can prune", but no such task existed. Result:

  - `revoked_tokens` accumulated one row per logout (refresh_token
    revocation) and per password change (whole-cookie-batch revocation
    via `iat` watermark). On a moderately active deployment that's
    a five-figure row count per year, kept forever, even though the
    JTI is only useful until the original token's `exp` has passed.
  - `password_reset_tokens` retained every issued reset token even
    after `expires_at`, which both bloats the table and leaks the
    population of users who have ever used the reset flow (any
    admin with read access can trivially enumerate by querying the
    `user_id` column).

Both are GDPR-relevant: under Art. 5(1)(e) (storage limitation) we
should not retain personal-data-adjacent records past their stated
purpose. Both tables ship `expires_at` timestamps that ALREADY mark
"this row is useless after X" — the prune just acts on that contract.

The job runs once per hour. Hourly is enough because:
  - JTI replay-protection only needs the row UNTIL the token's `exp`
    fires (after that, decode_token() rejects the JWT regardless of
    revocation status, so the row is double-redundant).
  - Reset-token retention is bounded by `expires_at` (default 1h) —
    daily would be fine but hourly keeps the window tight without
    ratelimit-meaningful cost.

Idempotent — re-running mid-hour is a no-op on already-pruned rows.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import delete

from app.database import async_session_factory
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task
def cleanup_expired_auth_records():
    """Celery beat entry point — wraps the async cleanup with asyncio.run."""
    asyncio.run(_cleanup())


async def _cleanup():
    # Lazy imports to avoid pulling SQLAlchemy models at module-load
    # time (worker boot becomes a circular-import hazard otherwise —
    # same family of issue scan_tasks.py opted into in v2.4.19).
    from app.models.password_reset_token import PasswordResetToken
    from app.models.revoked_token import RevokedToken

    now = datetime.now(timezone.utc)

    async with async_session_factory() as db:
        # `revoked_tokens` and `password_reset_tokens` have no
        # `organization_id` — RLS doesn't apply, so no `SET LOCAL`
        # context is needed. The tables also have no SUPERUSER-bypass
        # concern (no per-tenant filter to slip through).
        revoked_result = await db.execute(
            delete(RevokedToken).where(RevokedToken.expires_at < now)
        )
        reset_result = await db.execute(
            delete(PasswordResetToken).where(PasswordResetToken.expires_at < now)
        )
        await db.commit()

        revoked_n = revoked_result.rowcount or 0
        reset_n = reset_result.rowcount or 0
        if revoked_n or reset_n:
            logger.info(
                "cleanup_expired_auth_records: pruned %d revoked_tokens, %d password_reset_tokens",
                revoked_n,
                reset_n,
            )
        else:
            logger.debug("cleanup_expired_auth_records: nothing to prune")

        return {"revoked_tokens": revoked_n, "password_reset_tokens": reset_n}
