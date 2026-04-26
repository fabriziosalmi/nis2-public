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
                    await session.execute(
                        text("SET LOCAL app.current_org_id = :v"),
                        {"v": str(org)},
                    )
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def setup_row_level_security() -> None:
    """Idempotently apply tenant-isolation RLS on every tenant-scoped table.

    Runs at API startup (lifespan). It is safe to run repeatedly; each
    iteration drops and recreates the policy. We use FORCE ROW LEVEL
    SECURITY so even the table owner cannot bypass the policy — that is
    the actual failsafe value.

    The fallback `current_setting('app.bypass_rls', true) = 'on'` lets
    Alembic migrations and admin scripts opt out by setting that GUC at
    the start of their transaction. See alembic/env.py.
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

    async with engine.begin() as conn:
        for tname in tenant_tables:
            try:
                await conn.execute(text(f"ALTER TABLE {tname} ENABLE ROW LEVEL SECURITY"))
                await conn.execute(text(f"ALTER TABLE {tname} FORCE ROW LEVEL SECURITY"))
                await conn.execute(text(f"DROP POLICY IF EXISTS tenant_isolation ON {tname}"))
                await conn.execute(text(
                    f"CREATE POLICY tenant_isolation ON {tname} {policy_sql}"
                ))
            except Exception as exc:
                # A missing table on first boot (before alembic upgrade) is
                # expected; log and continue. A real failure shows up in
                # postgres logs and the CI smoke tests below.
                logger.warning("RLS setup skipped for %s: %s", tname, exc)
    logger.info(
        "RLS policies applied to %d tenant tables: %s",
        len(tenant_tables),
        ", ".join(tenant_tables),
    )
