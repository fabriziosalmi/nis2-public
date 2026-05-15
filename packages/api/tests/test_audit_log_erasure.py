# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Tests for the audit-log erasure and retention policy.

Exercises the pure-logic parts of the GDPR Art. 17 / NIS2 Art. 21
conflict resolution without a database or network:

  - The audit_log_retention_days setting default and env-override.
  - The cleanup_tasks return shape now includes 'audit_logs'.
  - The pseudonymisation SQL contains the required column updates.
"""
from __future__ import annotations

from datetime import timedelta

import pytest


# ---------------------------------------------------------------------------
# Settings: audit_log_retention_days
# ---------------------------------------------------------------------------

class TestAuditLogRetentionSetting:
    def test_default_is_90_days(self) -> None:
        from app.config import Settings
        s = Settings(
            environment="development",
            jwt_secret="x" * 32,
        )
        assert s.audit_log_retention_days == 90

    def test_can_override_via_field(self) -> None:
        from app.config import Settings
        s = Settings(
            environment="development",
            jwt_secret="x" * 32,
            audit_log_retention_days=365,
        )
        assert s.audit_log_retention_days == 365

    def test_cutoff_derived_correctly(self) -> None:
        from datetime import datetime, timezone
        from app.config import Settings
        s = Settings(
            environment="development",
            jwt_secret="x" * 32,
            audit_log_retention_days=30,
        )
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=s.audit_log_retention_days)
        assert (now - cutoff).days == 30


# ---------------------------------------------------------------------------
# cleanup_tasks: return shape includes audit_logs key
# ---------------------------------------------------------------------------

class TestCleanupTasksReturnShape:
    def test_return_dict_has_audit_logs_key(self) -> None:
        import pathlib

        src = pathlib.Path(
            "app/tasks/cleanup_tasks.py"
        ).read_text()
        # The function must return a dict with an 'audit_logs' key.
        assert '"audit_logs"' in src or "'audit_logs'" in src, (
            "cleanup_tasks._cleanup() must return an 'audit_logs' count"
        )

    def test_audit_logs_delete_uses_cutoff(self) -> None:
        import pathlib
        src = pathlib.Path("app/tasks/cleanup_tasks.py").read_text()
        assert "audit_logs" in src
        assert "cutoff" in src
        assert "audit_log_retention_days" in src


# ---------------------------------------------------------------------------
# Pseudonymisation SQL: all required columns are scrubbed
# ---------------------------------------------------------------------------

class TestPseudonymisationSQL:
    def _erasure_sql(self) -> str:
        import pathlib
        src = pathlib.Path("app/routers/auth.py").read_text()
        # Extract the UPDATE audit_logs statement.
        start = src.find("UPDATE audit_logs SET")
        assert start != -1, "Could not find UPDATE audit_logs in auth.py"
        end = src.find("WHERE user_id = :uid", start)
        return src[start:end]

    def test_user_id_nulled(self) -> None:
        assert "user_id = NULL" in self._erasure_sql()

    def test_ip_address_scrubbed(self) -> None:
        assert "ip_address" in self._erasure_sql()

    def test_user_agent_scrubbed(self) -> None:
        assert "user_agent" in self._erasure_sql()

    def test_details_nulled(self) -> None:
        assert "details = NULL" in self._erasure_sql(), (
            "details JSONB must be NULLed on erasure to remove linkable UUIDs"
        )


# ---------------------------------------------------------------------------
# Conflict resolution: explicit documentation in both source files
# ---------------------------------------------------------------------------

class TestConflictDocumentation:
    def test_auth_py_documents_gdpr_nis2_conflict(self) -> None:
        import pathlib
        src = pathlib.Path("app/routers/auth.py").read_text()
        assert "NIS2 Art. 21" in src
        assert "GDPR Art. 17" in src or "Art. 17" in src

    def test_cleanup_tasks_documents_retention_conflict(self) -> None:
        import pathlib
        src = pathlib.Path("app/tasks/cleanup_tasks.py").read_text()
        assert "NIS2" in src
        assert "AUDIT_LOG_RETENTION_DAYS" in src

    def test_privacy_md_documents_explicit_resolution(self) -> None:
        import pathlib
        # Privacy doc is three levels up from packages/api/
        privacy = pathlib.Path("../../docs/privacy.md")
        if not privacy.exists():
            privacy = pathlib.Path("docs/privacy.md")
        if not privacy.exists():
            pytest.skip("privacy.md not found relative to test CWD")
        text = privacy.read_text()
        assert "GDPR Art. 17 vs NIS2 Art. 21" in text
        assert "pseudonymisation" in text.lower()
        assert "details" in text
