# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""A scan abandoned by a dead worker must not stay `running` for ever.

The write path commits `status = "running"` in its own transaction before any
work begins, and the terminal state is written by an except handler eighty lines
later. Between those two commits the database says a scan is running and no
process owns it. A SIGKILL — an out-of-memory kill during a large CIDR expansion
is the realistic trigger — skips the handler entirely.

Celery's acks_late covers the common case by redelivering the message, but that
is a broker guarantee on Redis, not a database one. The beat schedule contained
four periodic tasks and none of them looked at stale scans, so a lost message
left the row `running` permanently: the user saw a scan that never finished and
could not be retried, and no operator signal existed at all.
"""

from __future__ import annotations

import inspect
from datetime import timedelta


class TestTheReaperIsScheduled:
    def test_the_task_exists(self):
        from app.tasks import scan_tasks

        assert hasattr(scan_tasks, "reap_stuck_scans")

    def test_it_is_in_the_beat_schedule(self):
        """A reaper nothing runs is the state this fixes."""
        from app.tasks.celery_app import celery_app

        tasks = {
            entry["task"] for entry in celery_app.conf.beat_schedule.values()
        }
        assert "app.tasks.scan_tasks.reap_stuck_scans" in tasks

    def test_it_runs_often_enough_to_matter_and_rarely_enough_to_be_cheap(self):
        from app.tasks.celery_app import celery_app

        entry = celery_app.conf.beat_schedule["reap-stuck-scans"]
        assert 600.0 <= entry["schedule"] <= 21600.0


class TestTheThresholdIsConservative:
    def test_the_window_is_generous(self):
        """A legitimately long scan must never be reaped from under a live
        worker: the cost of waiting is a stale row, the cost of being hasty is a
        lost result."""
        from app.tasks.scan_tasks import STUCK_SCAN_AFTER

        assert STUCK_SCAN_AFTER >= timedelta(hours=2)

    def test_it_only_touches_running_scans(self):
        from app.tasks import scan_tasks

        source = inspect.getsource(scan_tasks._reap_stuck_scans)
        assert 'Scan.status == "running"' in source
        for terminal in ('"completed"', '"pending"'):
            assert f"status == {terminal}" not in source

    def test_a_null_started_at_cannot_exempt_a_row(self):
        """started_at is nullable at the schema level, and a NULL comparison is
        NULL — which would silently exempt exactly the rows this task exists to
        find."""
        from app.tasks import scan_tasks

        source = inspect.getsource(scan_tasks._reap_stuck_scans)
        assert "func.coalesce(Scan.started_at, Scan.created_at)" in source


class TestWhatTheOperatorAndUserSee:
    def test_the_reaped_scan_is_marked_failed_with_a_reason(self):
        from app.tasks import scan_tasks

        source = inspect.getsource(scan_tasks._reap_stuck_scans)
        assert 'scan.status = "failed"' in source
        assert "scan.error_message" in source
        assert "did not report back" in source

    def test_it_tells_the_user_no_results_were_recorded(self):
        """Distinguishing "abandoned" from "finished badly" matters: the scan
        produced nothing, so the answer is to re-run it."""
        from app.tasks import scan_tasks

        source = inspect.getsource(scan_tasks._reap_stuck_scans)
        assert "no results were recorded" in source

    def test_each_reaping_is_logged(self):
        from app.tasks import scan_tasks

        source = inspect.getsource(scan_tasks._reap_stuck_scans)
        assert "logger.warning" in source

    def test_it_returns_a_count(self):
        from app.tasks import scan_tasks

        source = inspect.getsource(scan_tasks._reap_stuck_scans)
        assert '"reaped"' in source
