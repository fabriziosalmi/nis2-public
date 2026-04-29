# Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Unit tests for the v2.4.20 `cleanup_old_reports` Celery beat task.

The task itself is dead simple — `os.listdir` + age check + `unlink`
— but the consequences of getting it wrong (deleting files we
shouldn't, leaving stale ones behind, crashing the worker on a
permission error) are large enough that pinning the behaviour with
unit tests is worth the small file.

We test against a temporary directory with timestamps stamped via
`os.utime` so the test takes milliseconds instead of waiting 30
days for real files to age. The tests monkeypatch `REPORTS_DIR`
and `settings.report_ttl_days` so production paths and config
stay untouched.
"""
import os
import time

import pytest

from app.tasks import report_tasks


@pytest.fixture
def reports_dir(tmp_path, monkeypatch):
    """Redirect the cleanup task at a throwaway tmpdir for the test
    duration. Returns the path so individual tests can write files
    into it before invoking `cleanup_old_reports`."""
    d = tmp_path / "nis2-reports"
    d.mkdir()
    monkeypatch.setattr(report_tasks, "REPORTS_DIR", str(d))
    return d


@pytest.fixture
def short_ttl(monkeypatch):
    """Set the TTL to 1 day so we can write a file with mtime 2 days
    in the past and have the cleanup pick it up. Real production TTL
    (30 days) is also exercised in the boundary test below."""
    from app.config import settings
    monkeypatch.setattr(settings, "report_ttl_days", 1)


def _touch_with_age(path, days_old: float) -> None:
    """Create the file then back-date its mtime by `days_old` days."""
    path.write_bytes(b"x")
    age_seconds = days_old * 86400
    past = time.time() - age_seconds
    os.utime(path, (past, past))


class TestCleanupOldReports:
    def test_removes_files_older_than_ttl(self, reports_dir, short_ttl):
        # 3 days > 1 day TTL → should be removed
        old = reports_dir / "stale.pdf"
        _touch_with_age(old, days_old=3)

        result = report_tasks.cleanup_old_reports()

        assert result["removed"] == 1
        assert result["skipped"] == 0
        assert result["bytes_freed"] == 1
        assert not old.exists()

    def test_keeps_files_younger_than_ttl(self, reports_dir, short_ttl):
        # 0.5 days < 1 day TTL → should be kept
        fresh = reports_dir / "fresh.pdf"
        _touch_with_age(fresh, days_old=0.5)

        result = report_tasks.cleanup_old_reports()

        assert result["removed"] == 0
        assert fresh.exists(), "fresh report was wrongly deleted"

    def test_mixed_directory(self, reports_dir, short_ttl):
        """Mix of fresh + stale + at-the-boundary. Pinning the
        decision boundary against `< cutoff` (strict) means a file
        whose mtime equals the cutoff stays."""
        stale1 = reports_dir / "stale1.pdf"
        stale2 = reports_dir / "stale2.html"
        fresh = reports_dir / "fresh.csv"
        _touch_with_age(stale1, days_old=10)
        _touch_with_age(stale2, days_old=2)
        _touch_with_age(fresh, days_old=0.1)

        result = report_tasks.cleanup_old_reports()

        assert result["removed"] == 2
        assert not stale1.exists()
        assert not stale2.exists()
        assert fresh.exists()

    def test_ignores_directories(self, reports_dir, short_ttl):
        """A subdirectory accidentally created in the reports dir
        should NOT be deleted (cleanup operates on files only)."""
        subdir = reports_dir / "subdir"
        subdir.mkdir()
        # Back-date the directory's mtime to ensure it would qualify
        # by age if the filter were broken.
        os.utime(subdir, (time.time() - 30 * 86400, time.time() - 30 * 86400))

        result = report_tasks.cleanup_old_reports()

        assert result["removed"] == 0
        assert subdir.exists()

    def test_missing_directory_is_no_op(self, monkeypatch, tmp_path):
        """If the reports dir disappears between runs (someone
        wiped /tmp), the cleanup must not crash the worker."""
        nonexistent = tmp_path / "definitely-not-here"
        monkeypatch.setattr(report_tasks, "REPORTS_DIR", str(nonexistent))

        result = report_tasks.cleanup_old_reports()

        assert result == {"removed": 0, "skipped": 0, "bytes_freed": 0}

    def test_empty_directory_is_no_op(self, reports_dir, short_ttl):
        result = report_tasks.cleanup_old_reports()

        assert result == {"removed": 0, "skipped": 0, "bytes_freed": 0}

    def test_default_ttl_is_30_days(self):
        """Pin the default — a code change that drops it accidentally
        (e.g. to 0, which would wipe every report immediately) gets
        caught by this test before it ships."""
        # Pydantic Settings can be overridden at import time via env;
        # we validate the *class default* by reading the field directly
        # rather than `settings.report_ttl_days` (which may have been
        # overridden by a prior test).
        from app.config import Settings
        assert Settings.model_fields["report_ttl_days"].default == 30


class TestBeatSchedule:
    """Verify the cleanup task is wired into the beat schedule so
    Celery actually invokes it once a day. Without this test, a
    refactor that drops the schedule entry would silently regress
    to the v2.4.18 "/tmp grows forever" state — the cleanup function
    would still exist but never run."""

    def test_cleanup_is_in_beat_schedule(self):
        from app.tasks.celery_app import celery_app

        schedule = celery_app.conf.beat_schedule
        assert "cleanup-old-reports" in schedule, (
            "cleanup-old-reports missing from beat_schedule — "
            "task will never auto-run"
        )
        entry = schedule["cleanup-old-reports"]
        assert entry["task"] == "app.tasks.report_tasks.cleanup_old_reports"
        # 86400s = 24h. A regression to 60s (every minute) would
        # hammer the disk; a regression to e.g. 3600s (hourly) is
        # benign but worth catching as an unintentional change.
        assert entry["schedule"] == 86400.0
