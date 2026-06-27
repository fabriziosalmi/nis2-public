import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool, text
from sqlalchemy.ext.asyncio import async_engine_from_config

from app.config import settings
from app.database import Base

# Import all models so they are registered with Base.metadata.
# P0-01 audit fix: this list must be exhaustive — any model missing
# here will be silently ignored by `alembic revision --autogenerate`.
# The original list was missing Vendor, Incident, BusinessProcess,
# PasswordResetToken, GovernanceItem, and IncidentReport.
from app.models import (  # noqa: F401
    ApiKey,
    Asset,
    AuditLog,
    BusinessProcess,
    Finding,
    Incident,
    Membership,
    NotificationChannel,
    Organization,
    PasswordResetToken,
    RevokedToken,
    Scan,
    ScanResult,
    ScanSchedule,
    User,
    Vendor,
)
# Inline-defined models in routers. They inherit from Base so they
# must be imported here for metadata.create_all / autogenerate to
# see them.
from app.routers.governance import GovernanceItem  # noqa: F401
from app.routers.incidents import IncidentReport  # noqa: F401

# Alembic Config object
config = context.config

# Override sqlalchemy.url with the app setting
config.set_main_option("sqlalchemy.url", settings.database_url)

# Interpret the config file for Python logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        # Migrations run with FORCE ROW LEVEL SECURITY in effect. Bypass the
        # tenant policy so DDL/data migrations can touch all rows. Postgres
        # ignores the GUC for non-Postgres backends.
        #
        # This MUST be inside begin_transaction(): in SQLAlchemy 2.0 an
        # execute() *before* it autobegins a separate transaction that alembic
        # never owns, so on the async NullPool connection's close the whole
        # migration is silently rolled back — `alembic upgrade`/`stamp` log
        # "Running ..." and exit 0 but write nothing (found 2026-06-26).
        try:
            connection.execute(text("SET LOCAL app.bypass_rls = 'on'"))
        except Exception:
            pass
        context.run_migrations()


async def run_async_migrations() -> None:
    """Run migrations in 'online' mode with async engine."""
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = settings.database_url

    connectable = async_engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
