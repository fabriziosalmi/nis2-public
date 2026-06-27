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
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, text

from app.config import settings
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
    from app.models.organization import Organization
    from app.database import set_rls_org_context
    from sqlalchemy import select

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

        # GDPR Art. 5(1)(e) — prune audit_log rows older than the configured
        # retention ceiling (default 90 days; see settings.audit_log_retention_days).
        #
        # Conflict note: NIS2 Art. 21 recommends retaining security-incident
        # evidence for at least 12 months. Operators running the platform as a
        # security-incident management tool should raise AUDIT_LOG_RETENTION_DAYS
        # to ≥ 365 in their .env. The 90-day default satisfies GDPR storage
        # limitation for typical deployments while remaining auditable.
        #
        # Pseudonymised rows (user_id IS NULL) are pruned on the same schedule —
        # the event type still provides forensic value after erasure, but once
        # the retention ceiling passes, even the anonymised record has no further
        # legitimate purpose for the controller.
        cutoff = now - timedelta(days=settings.audit_log_retention_days)
        # H5: audit_logs is org-scoped, so under a NOSUPERUSER NOBYPASSRLS role a
        # single cross-tenant DELETE matches 0 rows. Walk the orgs, scope the
        # session per-org, and purge each org's expired rows. The explicit
        # organization_id filter keeps it correct under the superuser role too.
        # (Also fixes a pre-existing miss: the old single DELETE was never
        # committed — the only commit above covered just the token purges — so the
        # audit retention purge silently rolled back on session close.)
        audit_n = 0
        org_ids = (await db.execute(select(Organization.id))).scalars().all()
        for _org_id in org_ids:
            await set_rls_org_context(db, str(_org_id))
            _r = await db.execute(
                text(
                    "DELETE FROM audit_logs "
                    "WHERE created_at < :cutoff AND organization_id = :org"
                ),
                {"cutoff": cutoff, "org": str(_org_id)},
            )
            audit_n += _r.rowcount or 0
        await db.commit()

        revoked_n = revoked_result.rowcount or 0
        reset_n = reset_result.rowcount or 0
        if revoked_n or reset_n or audit_n:
            logger.info(
                "cleanup_expired_auth_records: pruned %d revoked_tokens, "
                "%d password_reset_tokens, %d audit_logs",
                revoked_n,
                reset_n,
                audit_n,
            )
        else:
            logger.debug("cleanup_expired_auth_records: nothing to prune")

        return {
            "revoked_tokens": revoked_n,
            "password_reset_tokens": reset_n,
            "audit_logs": audit_n,
        }
