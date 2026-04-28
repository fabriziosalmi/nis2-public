# Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import logging
import os
from collections.abc import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool

from app.config import settings

logger = logging.getLogger(__name__)

# Postgres-only: SET LOCAL is a Postgres feature; on SQLite (test envs)
# we silently skip the RLS scoping.
IS_POSTGRES = settings.database_url.startswith(("postgresql", "postgres"))

# Integration tests create a fresh TestClient per test, which means a new
# asyncio event loop per test. SQLAlchemy's default pooled connections get
# attached to whichever loop first checks them out — reuse from a different
# loop raises "Future attached to a different loop" / "Event loop is closed".
# NullPool sidesteps this: each request opens a fresh asyncpg connection
# and closes it on release. The performance hit is irrelevant in tests
# and never reaches production.
_INTEGRATION_TEST_MODE = os.environ.get("INTEGRATION_DB") == "1"

if _INTEGRATION_TEST_MODE:
    engine: AsyncEngine = create_async_engine(
        settings.database_url,
        echo=False,
        poolclass=NullPool,
    )
else:
    engine = create_async_engine(
        settings.database_url,
        echo=False,
        pool_size=20,
        max_overflow=10,
        pool_pre_ping=True,
    )

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield an AsyncSession, scoping the transaction to the current
    organisation id (from IdentityMiddleware) so Postgres RLS policies
    see the right value of `app.current_org_id`. SET LOCAL is bound to
    the transaction, so connection pool reuse is safe — the next
    transaction starts with the setting cleared.
    """
    # Imported lazily to avoid a circular import (middleware/identity ->
    # app.utils.jwt -> app.config -> app.database -> ...).
    from app.middleware.identity import current_org_id

    async with async_session_factory() as session:
        try:
            if IS_POSTGRES:
                org = current_org_id.get()
                if org is not None:
                    # `SET LOCAL` does not accept bind parameters in
                    # Postgres; `set_config(..., is_local=true)` is the
                    # parameterised equivalent and is transaction-scoped.
                    await session.execute(
                        text("SELECT set_config('app.current_org_id', :v, true)"),
                        {"v": str(org)},
                    )
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def ensure_schema() -> None:
    """Best-effort idempotent schema bootstrap.

    The repo does not yet ship Alembic migration files (alembic/versions/
    is empty). Until that gap is closed, we let the FastAPI lifespan
    create missing tables and apply the small set of known column
    additions, so a fresh `docker compose up` works without manual SQL
    and existing volumes auto-heal on restart.

    DEBT: this is not a substitute for migrations. It cannot rename
    columns, drop columns safely, alter types, or coordinate data
    backfills. Generate proper Alembic revisions before any production
    deployment.
    """
    if not IS_POSTGRES:
        # SQLite-backed tests do their own create_all in conftest.
        return

    # 1. Create any tables defined in the ORM that don't exist yet.
    #    On a populated DB this is a fast no-op.
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # 2. Known columns added after the initial schema. ADD COLUMN IF NOT
    #    EXISTS is idempotent and cheap. Each entry is a (table, column,
    #    type) tuple — keep it short and append, never rewrite history.
    additive_columns: list[tuple[str, str, str]] = [
        # v2.4.0: DNS rebinding TOCTOU mitigation pins the resolved IP
        # at create-time so the scanner cannot be redirected to a private
        # range between validation and connection.
        ("assets", "pinned_ip", "VARCHAR(45)"),
        # v2.4.13: password-change session invalidation watermark.
        # NULL on existing rows = "never rotated" — the iat check
        # treats the token's iat as fresher than NULL automatically.
        ("users", "password_changed_at", "TIMESTAMP WITH TIME ZONE"),
    ]
    async with engine.begin() as conn:
        for table, column, ddl in additive_columns:
            try:
                await conn.execute(
                    text(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {ddl}")
                )
            except Exception as exc:
                # If the table itself doesn't exist yet on this engine
                # (e.g. metadata mismatch), log and move on — RLS setup
                # below logs the same way and CI catches real breakage.
                logger.warning("ensure_schema: %s.%s skipped: %s", table, column, exc)


async def setup_row_level_security() -> None:
    """Idempotently apply tenant-isolation RLS on every tenant-scoped table.

    Runs at API startup (lifespan). It is safe to run repeatedly; each
    iteration drops and recreates the policy. We use FORCE ROW LEVEL
    SECURITY so even the table owner cannot bypass the policy — that is
    the actual failsafe value.

    The fallback `current_setting('app.bypass_rls', true) = 'on'` lets
    Alembic migrations and admin scripts opt out by setting that GUC at
    the start of their transaction. See alembic/env.py.

    Each table is wrapped in its own transaction (engine.begin per
    iteration) so that a single failing ALTER (e.g. a table that doesn't
    exist on this deployment) does NOT poison the whole batch with
    InFailedSQLTransactionError.
    """
    if not IS_POSTGRES:
        logger.debug("setup_row_level_security: skipping (not Postgres)")
        return

    # Discover tenant-scoped tables from SQLAlchemy metadata.
    tenant_tables = sorted(
        t.name for t in Base.metadata.tables.values()
        if "organization_id" in t.columns
    )
    if not tenant_tables:
        logger.warning("setup_row_level_security: no tenant tables found")
        return

    policy_sql = (
        "USING (organization_id::text = current_setting('app.current_org_id', true) "
        "OR current_setting('app.bypass_rls', true) = 'on')"
    )

    applied: list[str] = []
    skipped: list[str] = []
    for tname in tenant_tables:
        # Per-table transaction. The previous single-transaction version
        # aborted on the first failure and `InFailedSQLTransactionError`
        # silently disabled RLS on every table after that — exactly the
        # silent failure mode RLS is supposed to prevent.
        try:
            async with engine.begin() as conn:
                await conn.execute(text(f"ALTER TABLE {tname} ENABLE ROW LEVEL SECURITY"))
                await conn.execute(text(f"ALTER TABLE {tname} FORCE ROW LEVEL SECURITY"))
                await conn.execute(text(f"DROP POLICY IF EXISTS tenant_isolation ON {tname}"))
                await conn.execute(text(
                    f"CREATE POLICY tenant_isolation ON {tname} {policy_sql}"
                ))
            applied.append(tname)
        except Exception as exc:
            logger.warning("RLS setup skipped for %s: %s", tname, exc)
            skipped.append(tname)

    logger.info(
        "RLS policies applied to %d/%d tenant tables (skipped: %s)",
        len(applied),
        len(tenant_tables),
        ", ".join(skipped) if skipped else "none",
    )
