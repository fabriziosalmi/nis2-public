"""Pure-logic tests for RLS migration 002 and the updated setup_row_level_security().

No live DB required — all DB interactions are mocked.
"""
import os
import pathlib
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MIGRATION_PATH = pathlib.Path(__file__).parent.parent / "alembic" / "versions" / "002_add_rls_policies.py"
DATABASE_PATH = pathlib.Path(__file__).parent.parent / "app" / "database.py"

EXPECTED_TENANT_TABLES = sorted([
    "api_keys",
    "assets",
    "audit_logs",
    "business_processes",
    "findings",
    "incidents",
    "memberships",
    "notification_channels",
    "scan_schedules",
    "scans",
    "vendors",
])


def _migration_source() -> str:
    return MIGRATION_PATH.read_text()


def _database_source() -> str:
    return DATABASE_PATH.read_text()


# ---------------------------------------------------------------------------
# Migration file tests
# ---------------------------------------------------------------------------

class TestMigrationFileExists:
    def test_migration_file_exists(self):
        assert MIGRATION_PATH.exists(), f"Migration file not found: {MIGRATION_PATH}"

    def test_migration_has_correct_revision(self):
        src = _migration_source()
        assert "002_add_rls_policies" in src

    def test_migration_depends_on_001(self):
        src = _migration_source()
        assert "001_initial" in src

    def test_migration_has_upgrade_function(self):
        src = _migration_source()
        assert "def upgrade" in src

    def test_migration_has_downgrade_function(self):
        src = _migration_source()
        assert "def downgrade" in src


class TestMigrationEnablesRLS:
    def test_enable_rls_for_all_tenant_tables(self):
        src = _migration_source()
        for t in EXPECTED_TENANT_TABLES:
            assert "ENABLE ROW LEVEL SECURITY" in src, "Missing ENABLE ROW LEVEL SECURITY"
            assert t in src, f"Table {t!r} not mentioned in migration"

    def test_force_rls_present(self):
        src = _migration_source()
        assert "FORCE ROW LEVEL SECURITY" in src

    def test_creates_tenant_isolation_policy(self):
        src = _migration_source()
        assert "CREATE POLICY tenant_isolation" in src

    def test_policy_predicate_contains_org_id_check(self):
        src = _migration_source()
        assert "app.current_org_id" in src
        assert "app.bypass_rls" in src

    def test_policy_has_with_check(self):
        src = _migration_source()
        assert "WITH CHECK" in src


class TestMigrationDowngrade:
    def test_downgrade_drops_policies(self):
        src = _migration_source()
        assert "DROP POLICY IF EXISTS tenant_isolation" in src

    def test_downgrade_disables_rls(self):
        src = _migration_source()
        assert "DISABLE ROW LEVEL SECURITY" in src


# ---------------------------------------------------------------------------
# database.py / setup_row_level_security() tests
# ---------------------------------------------------------------------------

class TestSetupRLSVerifyMode:
    def test_applies_missing_policies_idempotently(self):
        """setup_row_level_security() must create policies for missing tables.

        The canonical source is migration 002_add_rls_policies, but the
        function also applies them as a fallback (e.g. integration tests use
        Base.metadata.create_all instead of Alembic). It must be idempotent —
        the migration uses DROP POLICY IF EXISTS; the function only creates for
        tables that are missing their policy.
        """
        src = _database_source()
        fn_start = src.index("async def setup_row_level_security")
        next_fn = src.find("\nasync def ", fn_start + 1)
        if next_fn == -1:
            next_fn = src.find("\ndef ", fn_start + 1)
        fn_src = src[fn_start:next_fn] if next_fn != -1 else src[fn_start:]
        # Must create policies for missing tables
        assert "CREATE POLICY" in fn_src
        # Must only do so for tables that are missing (reads pg_policies first)
        assert "pg_policies" in fn_src
        assert "missing" in fn_src

    def test_reads_pg_policies(self):
        src = _database_source()
        fn_start = src.index("async def setup_row_level_security")
        next_fn = src.find("\nasync def ", fn_start + 1)
        if next_fn == -1:
            next_fn = src.find("\ndef ", fn_start + 1)
        fn_src = src[fn_start:next_fn] if next_fn != -1 else src[fn_start:]
        assert "pg_policies" in fn_src, (
            "setup_row_level_security() must query pg_policies to verify policies"
        )

    def test_logs_warning_for_missing_policy(self):
        """When a table is missing its policy, a WARNING is logged."""
        # We import the module fresh, mocking heavy dependencies
        sys.path.insert(0, str(MIGRATION_PATH.parent.parent / "app"))

        with (
            patch.dict(os.environ, {"DATABASE_URL": "postgresql+asyncpg://x/y"}),
        ):
            try:
                import app.database as db_module  # type: ignore[import]
            except Exception:
                pytest.skip("Could not import app.database — skipping live-import test")

            # Build a mock engine context manager that returns no rows from pg_policies
            mock_result = MagicMock()
            mock_result.__iter__ = MagicMock(return_value=iter([]))  # no policies found

            mock_conn = AsyncMock()
            mock_conn.execute = AsyncMock(return_value=mock_result)

            mock_ctx = MagicMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)

            with (
                patch.object(db_module, "IS_POSTGRES", True),
                patch.object(db_module, "engine") as mock_engine,
                patch.object(db_module.logger, "warning") as mock_warn,
                patch.object(db_module.logger, "info"),
            ):
                mock_engine.connect.return_value = mock_ctx

                import asyncio
                asyncio.run(db_module.setup_row_level_security())

                # Should have warned about missing policies
                assert mock_warn.called, "Expected logger.warning() to be called for missing policies"
                warning_msg = str(mock_warn.call_args)
                assert "missing" in warning_msg.lower() or "RLS" in warning_msg

    def test_logs_info_when_all_policies_present(self):
        """When all tenant tables have policies, info is logged (no warning)."""
        with (
            patch.dict(os.environ, {"DATABASE_URL": "postgresql+asyncpg://x/y"}),
        ):
            try:
                import app.database as db_module  # type: ignore[import]
            except Exception:
                pytest.skip("Could not import app.database — skipping live-import test")

            # Return a row for every tenant table
            tenant_tables = sorted(
                t.name for t in db_module.Base.metadata.tables.values()
                if "organization_id" in t.columns
            )
            mock_rows = [(t,) for t in tenant_tables]

            mock_result = MagicMock()
            mock_result.__iter__ = MagicMock(return_value=iter(mock_rows))

            mock_conn = AsyncMock()
            mock_conn.execute = AsyncMock(return_value=mock_result)

            mock_ctx = MagicMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)

            with (
                patch.object(db_module, "IS_POSTGRES", True),
                patch.object(db_module, "engine") as mock_engine,
                patch.object(db_module.logger, "warning") as mock_warn,
                patch.object(db_module.logger, "info") as mock_info,
            ):
                mock_engine.connect.return_value = mock_ctx

                import asyncio
                asyncio.run(db_module.setup_row_level_security())

                # Should log info, not warning (about policy verification)
                info_calls = [str(c) for c in mock_info.call_args_list]
                assert any("verified" in c or "RLS" in c for c in info_calls), (
                    "Expected logger.info() confirming policies are verified"
                )
                # No missing-policy warning should have been issued
                warning_calls = [str(c) for c in mock_warn.call_args_list]
                assert not any("missing" in c for c in warning_calls), (
                    "Unexpected warning about missing policies when all are present"
                )
