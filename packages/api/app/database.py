# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
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

# v2.4.19 hotfix: the same "Future attached to different loop" trap
# fires inside the Celery worker. `run_scan_task` calls `asyncio.run`
# per task, which mints a FRESH event loop each invocation; the
# pooled asyncpg connection (held over from the previous task) is
# bound to a now-CLOSED loop, and SQLAlchemy throws on the next
# query. Symptom we hit in v2.4.18: a scan ran once successfully,
# the second scan submission errored with `RuntimeError: Event loop
# is closed`.
#
# Detection via env var (set in infra/docker/docker-compose.dev.yml
# for the celery-worker + celery-beat services). NullPool gives each
# task a fresh asyncpg connection — same fix as the integration
# tests, same "performance hit irrelevant for the workload"
# justification (tasks run end-to-end in seconds, not milliseconds,
# so the cost of opening a connection is amortised away).
_CELERY_WORKER_MODE = os.environ.get("CELERY_WORKER") == "1"

if _INTEGRATION_TEST_MODE or _CELERY_WORKER_MODE:
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
    """Best-effort idempotent schema bootstrap (dev / first-run convenience).

    P0-01 audit (v2.5.5): the initial Alembic migration now exists at
    ``alembic/versions/001_initial_schema.py``. The recommended path for
    production and CI is::

        alembic upgrade head      # new database
        alembic stamp head        # existing database, first time using Alembic

    This function is **kept** as a degraded-mode fallback so a bare
    ``docker compose up`` still works without running ``alembic`` first.
    It cannot rename/drop columns, alter types, or coordinate data
    backfills — any non-additive change MUST go through an Alembic
    revision.
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
    # v2.4.14: PasswordResetToken is a brand-new table; create_all above
    # already provisions it, no ALTER needed. Listed here for the
    # changelog grep — see app/models/password_reset_token.py.
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


_RLS_PREDICATE = (
    "(organization_id::text = current_setting('app.current_org_id', true) "
    "OR current_setting('app.bypass_rls', true) = 'on')"
)


async def setup_row_level_security() -> None:
    """Ensure RLS policies are in place for all tenant-scoped tables.

    Policies are canonically created by Alembic migration 002_add_rls_policies.
    This function checks which tables are missing their policy and creates them
    idempotently — the same logic as the migration. This allows the integration
    test bootstrap (which uses Base.metadata.create_all rather than Alembic) to
    set up RLS without requiring a full migration run.

    In a properly migrated production database all policies will already exist,
    so the CREATE statements are skipped entirely. In tests or a bare create_all
    bootstrap they are applied here.

    Also checks whether the app DB role is SUPERUSER or BYPASSRLS, which
    would make all RLS policies decorative. In production this causes the
    API to refuse startup unless RLS_SUPERUSER_OK=1 is set.
    """
    if not IS_POSTGRES:
        logger.debug("setup_row_level_security: skipping (not Postgres)")
        return

    tenant_tables = sorted(
        t.name for t in Base.metadata.tables.values()
        if "organization_id" in t.columns
    )

    async with engine.connect() as conn:
        result = await conn.execute(
            text("SELECT tablename FROM pg_policies WHERE policyname = 'tenant_isolation'")
        )
        has_policy = {row[0] for row in result}

    missing = [t for t in tenant_tables if t not in has_policy]
    if missing:
        logger.warning(
            "RLS: tenant_isolation policy missing on %d table(s): %s — applying now.",
            len(missing), ", ".join(missing),
        )
        async with engine.begin() as conn:
            for t in missing:
                await conn.execute(text(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY"))
                await conn.execute(text(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY"))
                await conn.execute(
                    text(f"CREATE POLICY tenant_isolation ON {t} "
                         f"USING {_RLS_PREDICATE} "
                         f"WITH CHECK {_RLS_PREDICATE}")
                )
        logger.info("RLS: tenant_isolation policies applied on %d table(s).", len(missing))
    else:
        logger.info("RLS: tenant_isolation policies verified on %d tables.", len(tenant_tables))

    # Defence-in-depth check: if the application's Postgres role is a
    # SUPERUSER (or has BYPASSRLS), RLS policies are bypassed for this role.
    # In production the API refuses to start unless RLS_SUPERUSER_OK=1 is set.
    try:
        async with engine.connect() as conn:
            result = await conn.execute(text(
                "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
            ))
            row = result.first()
            if row and (row[0] or row[1]):
                msg = (
                    f"DB role has rolsuper={row[0]} rolbypassrls={row[1]} — RLS policies "
                    "are BYPASSED for this role. Tenant isolation currently relies on "
                    "application-layer org_id filters ONLY. Provision a non-superuser "
                    "app role with BYPASSRLS revoked before going live, e.g.:\n"
                    "  ALTER ROLE <app_role> NOSUPERUSER NOBYPASSRLS;"
                )
                if settings.environment == "production" and \
                        os.environ.get("RLS_SUPERUSER_OK") != "1":
                    logger.error("%s", msg)
                    raise RuntimeError(
                        "Refusing to start: production deploy with a SUPERUSER/BYPASSRLS app role. "
                        "Either provision a non-superuser app role, or set RLS_SUPERUSER_OK=1 "
                        "explicitly in the environment to opt out (NOT recommended)."
                    )
                logger.warning("%s", msg)
    except RuntimeError:
        raise
    except Exception as exc:
        logger.debug("RLS role-attribute check skipped: %s", exc)
