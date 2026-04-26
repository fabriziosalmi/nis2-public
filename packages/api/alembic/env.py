import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool, text
from sqlalchemy.ext.asyncio import async_engine_from_config

from app.config import settings
from app.database import Base

# Import all models so they are registered with Base.metadata
from app.models import (  # noqa: F401
    ApiKey,
    Asset,
    AuditLog,
    Finding,
    Membership,
    NotificationChannel,
    Organization,
    RevokedToken,
    Scan,
    ScanResult,
    ScanSchedule,
    User,
)

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
    # Migrations run with FORCE ROW LEVEL SECURITY in effect. Bypass the
    # tenant policy explicitly so DDL and any data migrations can touch
    # all rows. Postgres ignores the GUC for non-Postgres backends.
    try:
        connection.execute(text("SET LOCAL app.bypass_rls = 'on'"))
    except Exception:
        pass
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
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
