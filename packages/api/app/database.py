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
    from app.middleware.identity import current_org_id, current_user_id

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
                uid = current_user_id.get()
                if uid is not None:
                    await session.execute(
                        text("SELECT set_config('app.current_user_id', :v, true)"),
                        {"v": str(uid)},
                    )
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def set_rls_org_context(session: AsyncSession, org_id, user_id=None) -> None:
    """Set the RLS org context on a Celery/background-task session (H5).

    The API does this in get_db from IdentityMiddleware ContextVars; the worker
    has no request context, so each task must set `app.current_org_id` explicitly
    with the org id of the entity it operates on. Without it, every tenant-scoped
    query returns 0 rows under a NOSUPERUSER NOBYPASSRLS role (and the audit-log
    retention DELETE removes 0 rows).

    Unlike get_db this uses `is_local => false` (session/connection-scoped, NOT
    transaction-scoped): a task issues several commits (scan -> running, then
    persist findings), and a transaction-scoped SET LOCAL would be cleared by the
    first commit, dropping context for the rest. Session scope is safe here ONLY
    because the worker runs with NullPool (CELERY_WORKER=1) — a fresh asyncpg
    connection per task, closed on release, so nothing leaks to another tenant's
    task. Do NOT call this on a pooled (API) connection.

    No-op on non-Postgres or when org_id is None (keeps the superuser/legacy path
    working unchanged).
    """
    if not IS_POSTGRES or org_id is None:
        return
    await session.execute(
        text("SELECT set_config('app.current_org_id', :v, false)"),
        {"v": str(org_id)},
    )
    if user_id is not None:
        await session.execute(
            text("SELECT set_config('app.current_user_id', :v, false)"),
            {"v": str(user_id)},
        )


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
        # MFA / TOTP (migrations 003, 006) and invite-by-token (migration 004)
        # were added to the User model after these tables may already exist on an
        # upgraded volume. create_all does NOT backfill columns, so without these
        # a dev who made their Postgres volume before the feature 500s on
        # register/login with "column users.totp_secret does not exist" (found in
        # the 2026-06-26 live validation). Types match the model + the migrations'
        # end state. Prod is unaffected — it runs Alembic.
        ("users", "totp_secret", "VARCHAR(256)"),
        ("users", "totp_enabled", "BOOLEAN NOT NULL DEFAULT FALSE"),
        ("users", "totp_recovery_codes", "VARCHAR(1024)"),
        ("users", "invite_token_hash", "VARCHAR(128)"),
        ("users", "invite_token_expires_at", "TIMESTAMP WITH TIME ZONE"),
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


# L1: data-table tenant isolation is scoped to the ACTIVE org only. The earlier
# predicate also OR'd in "any org the current user is a member of", which let a
# multi-org user's queries read EVERY org they belong to — not just the one they
# are acting in — an over-permissive defence-in-depth gap. app.current_org_id is
# set from the JWT's active org (get_db) or the API key's org (get_api_key_org),
# so this IS the correct tenant boundary. Membership-based access stays ONLY on
# the `memberships` table (_RLS_MEMBERSHIPS_PREDICATE) so a user can still read
# their own memberships to enumerate / switch orgs.
_RLS_PREDICATE = (
    "(organization_id::text = current_setting('app.current_org_id', true))"
)

_RLS_MEMBERSHIPS_PREDICATE = (
    "(organization_id::text = current_setting('app.current_org_id', true) "
    "OR user_id::text = current_setting('app.current_user_id', true))"
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
        t.name for t in Base.metadata.tables.values() if "organization_id" in t.columns
    )

    async with engine.connect() as conn:
        result = await conn.execute(
            text(
                "SELECT tablename FROM pg_policies WHERE policyname = 'tenant_isolation'"
            )
        )
        has_policy = {row[0] for row in result}

    missing = [t for t in tenant_tables if t not in has_policy]
    if missing:
        logger.warning(
            "RLS: tenant_isolation policy missing on %d table(s): %s — applying now.",
            len(missing),
            ", ".join(missing),
        )
        async with engine.begin() as conn:
            for t in missing:
                await conn.execute(text(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY"))
                await conn.execute(text(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY"))
                predicate = (
                    _RLS_MEMBERSHIPS_PREDICATE if t == "memberships" else _RLS_PREDICATE
                )
                await conn.execute(
                    text(
                        f"CREATE POLICY tenant_isolation ON {t} "
                        f"USING {predicate} "
                        f"WITH CHECK {predicate}"
                    )
                )
        logger.info(
            "RLS: tenant_isolation policies applied on %d table(s).", len(missing)
        )
    else:
        logger.info(
            "RLS: tenant_isolation policies verified on %d tables.", len(tenant_tables)
        )

    # L1: databases created before the active-org-only predicate still carry the
    # old membership-OR subquery in their tenant_isolation policy. Recreate any
    # such policy (detected by 'memberships' appearing in the qual of a
    # NON-memberships table) with the current _RLS_PREDICATE. Runs as the
    # superuser/migration role; no-ops (caught) once the app runs as nis2_app —
    # by then a privileged boot has already applied it.
    async with engine.connect() as conn:
        result = await conn.execute(
            text(
                "SELECT tablename FROM pg_policies "
                "WHERE policyname = 'tenant_isolation' "
                "AND tablename <> 'memberships' AND qual LIKE '%memberships%'"
            )
        )
        stale = [row[0] for row in result]
    for t in stale:
        try:
            async with engine.begin() as conn:
                await conn.execute(text(f"DROP POLICY tenant_isolation ON {t}"))
                await conn.execute(
                    text(
                        f"CREATE POLICY tenant_isolation ON {t} "
                        f"USING {_RLS_PREDICATE} WITH CHECK {_RLS_PREDICATE}"
                    )
                )
            logger.info("L1: recreated tenant_isolation on %s (active-org-only).", t)
        except Exception as exc:
            logger.warning("L1: could not recreate tenant_isolation on %s: %s", t, exc)

    # api_keys is a BOOTSTRAP table: get_api_key_org looks a key up BY key_hash to
    # DISCOVER its org, so that query runs with no app.current_org_id set — and the
    # org-scoped tenant_isolation policy would hide every row (0 results => every
    # API-key request 401s under a NOBYPASSRLS role). Add a SELECT-only policy that
    # permits the global hash lookup. PostgreSQL ORs permissive policies, so SELECT
    # becomes global while tenant_isolation still scopes INSERT/UPDATE/DELETE to the
    # caller's org. Hashes (not raw keys) are all that's readable, and the
    # management endpoints filter by org in the query. Idempotent.
    async with engine.begin() as conn:
        try:
            present = await conn.execute(
                text(
                    "SELECT 1 FROM pg_policies "
                    "WHERE tablename='api_keys' AND policyname='api_keys_lookup'"
                )
            )
            if present.first() is None:
                await conn.execute(
                    text("CREATE POLICY api_keys_lookup ON api_keys FOR SELECT USING (true)")
                )
                logger.info("RLS: api_keys_lookup (global SELECT) policy applied.")
        except Exception as exc:
            logger.warning("RLS: api_keys_lookup policy skipped: %s", exc)

    # M2: make audit_logs append-only for the application role. A plain REVOKE
    # would also break the retention purge in cleanup_tasks, so that purge runs
    # through purge_old_audit_logs() — a SECURITY DEFINER function owned by this
    # (privileged) setup role: it bypasses RLS and keeps DELETE even after the app
    # role loses it. SET search_path guards the definer fn against search-path
    # hijacking; EXECUTE is revoked from PUBLIC (the CREATE default) then granted
    # only to the app role. Each statement runs in its own transaction so a no-op
    # (role absent, or insufficient rights once running AS the app role) doesn't
    # abort the rest — these must be applied during a superuser/migration boot.
    _audit_appendonly_stmts = (
        (
            "CREATE OR REPLACE FUNCTION purge_old_audit_logs(retention_days integer) "
            "RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER "
            "SET search_path = public, pg_temp AS $fn$ "
            "DECLARE deleted bigint; "
            "BEGIN "
            "DELETE FROM audit_logs "
            "WHERE created_at < now() - make_interval(days => retention_days); "
            "GET DIAGNOSTICS deleted = ROW_COUNT; "
            "RETURN deleted; "
            "END; $fn$",
            "purge_old_audit_logs() function",
        ),
        (
            "REVOKE EXECUTE ON FUNCTION purge_old_audit_logs(integer) FROM PUBLIC",
            "lock down purge function (revoke EXECUTE from PUBLIC)",
        ),
        (
            "GRANT EXECUTE ON FUNCTION purge_old_audit_logs(integer) TO nis2_app",
            "grant purge EXECUTE to nis2_app",
        ),
        # GDPR Art. 17 erasure pseudonymises a user's audit rows (UPDATE) — also a
        # legitimate, privileged exception to append-only, so it runs through its
        # own SECURITY DEFINER function (auth.py calls it instead of a direct
        # UPDATE, which the REVOKE below would otherwise block under nis2_app).
        (
            "CREATE OR REPLACE FUNCTION pseudonymize_user_audit_logs(p_user_id uuid) "
            "RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER "
            "SET search_path = public, pg_temp AS $fn$ "
            "DECLARE updated bigint; "
            "BEGIN "
            "UPDATE audit_logs SET user_id = NULL, ip_address = '127.0.0.1', "
            "user_agent = '[erased]', details = NULL WHERE user_id = p_user_id; "
            "GET DIAGNOSTICS updated = ROW_COUNT; "
            "RETURN updated; "
            "END; $fn$",
            "pseudonymize_user_audit_logs() function",
        ),
        (
            "REVOKE EXECUTE ON FUNCTION pseudonymize_user_audit_logs(uuid) FROM PUBLIC",
            "lock down pseudonymize function (revoke EXECUTE from PUBLIC)",
        ),
        (
            "GRANT EXECUTE ON FUNCTION pseudonymize_user_audit_logs(uuid) TO nis2_app",
            "grant pseudonymize EXECUTE to nis2_app",
        ),
        (
            "REVOKE UPDATE, DELETE ON audit_logs FROM nis2_app",
            "make audit_logs append-only for nis2_app",
        ),
    )
    for _stmt, _desc in _audit_appendonly_stmts:
        try:
            async with engine.begin() as conn:
                await conn.execute(text(_stmt))
        except Exception as exc:
            logger.warning("M2: %s skipped: %s", _desc, exc)

    # Defence-in-depth: refuse to run with a SUPERUSER/BYPASSRLS role in prod
    # (shared with the Celery worker boot guard — see assert_db_role_rls_safe).
    await assert_db_role_rls_safe()


async def assert_db_role_rls_safe() -> None:
    """Refuse to run on a SUPERUSER/BYPASSRLS Postgres role in production.

    If the app's Postgres role is SUPERUSER or has BYPASSRLS, every RLS policy
    is decorative for that role and tenant isolation rests on application-layer
    org_id filters ONLY. In production we refuse to start unless
    RLS_SUPERUSER_OK=1 is set. Shared by the API lifespan
    (setup_row_level_security) and the Celery worker boot guard
    (tasks.celery_app) so both processes enforce the same posture — pre-fix the
    worker had NO guard and silently ran cross-tenant queries under superuser.
    """
    if not IS_POSTGRES:
        return
    try:
        async with engine.connect() as conn:
            result = await conn.execute(
                text(
                    "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
                )
            )
            row = result.first()
            if row and (row[0] or row[1]):
                msg = (
                    f"DB role has rolsuper={row[0]} rolbypassrls={row[1]} — RLS policies "
                    "are BYPASSED for this role. Tenant isolation currently relies on "
                    "application-layer org_id filters ONLY. Provision a non-superuser "
                    "app role with BYPASSRLS revoked before going live, e.g.:\n"
                    "  ALTER ROLE <app_role> NOSUPERUSER NOBYPASSRLS;"
                )
                if (
                    settings.environment == "production"
                    and os.environ.get("RLS_SUPERUSER_OK") != "1"
                ):
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
