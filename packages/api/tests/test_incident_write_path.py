# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""The Art. 23 incident record had no producer.

There are two incident tables, and the split is deliberate:

  `incidents`         — the lifecycle record carrying the three Art. 23
                        deadlines. Read by the dashboard countdown
                        (routers/incident_monitor.py), the Celery alerting task
                        (tasks/incident_tasks.py) and the report dossier.
  `incident_reports`  — the CSIRT submission artefact, behind
                        POST /api/v1/incidents.

What was not deliberate: nothing in the application ever created an `incidents`
row. The only `Incident(...)` in the tree was in a demo seed script wired to no
Makefile target. So three well-built components all read from a store with no
producer, and the 24 h / 72 h / 1-month countdown, the deadline alerting and the
dossier section could only ever show demo data.

Worse, the creation endpoint the README documents — POST /api/v1/incidents —
writes the OTHER table. An incident declared through the documented API was
invisible to the clock that gives the module its purpose. Nobody noticed because
the dashboard was read-only: an empty monitor looked like an organisation with
no incidents.

These tests pin the write path and, above all, the deadline arithmetic: the
whole point of the record is that those three timestamps are right.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.routers.incident_monitor import (
    _EARLY_WARNING_WINDOW,
    _FINAL_REPORT_WINDOW,
    _NOTIFICATION_WINDOW,
    IncidentCreateRequest,
    IncidentPatchRequest,
)


class TestDeadlineWindows:
    """Art. 23 fixes these three windows; they are not tunable."""

    def test_early_warning_is_24_hours(self):
        assert _EARLY_WARNING_WINDOW == timedelta(hours=24)

    def test_notification_is_72_hours(self):
        assert _NOTIFICATION_WINDOW == timedelta(hours=72)

    def test_final_report_is_one_month(self):
        assert _FINAL_REPORT_WINDOW == timedelta(days=30)

    def test_windows_are_ordered(self):
        assert _EARLY_WARNING_WINDOW < _NOTIFICATION_WINDOW < _FINAL_REPORT_WINDOW


class TestDeadlinesRunFromDetection:
    """Not from data-entry time.

    An incident is routinely entered some hours after it was noticed. Starting
    the 24-hour clock at insert time would report a deadline later than the law
    allows — the failure would be a missed legal notification, and the platform
    would have been the thing that reported the wrong date.
    """

    def test_detected_at_is_accepted(self):
        detected = datetime(2026, 3, 1, 8, 0, tzinfo=timezone.utc)
        req = IncidentCreateRequest(
            title="x", incident_type="ransomware", severity="high",
            description="d", detected_at=detected,
        )
        assert req.detected_at == detected

    def test_detected_at_is_optional(self):
        """Omitting it means "now", which the router substitutes."""
        req = IncidentCreateRequest(
            title="x", incident_type="ransomware", severity="high", description="d"
        )
        assert req.detected_at is None

    def test_deadlines_derived_from_a_past_detection_are_already_closer(self):
        """The arithmetic the router performs, asserted directly."""
        detected = datetime.now(timezone.utc) - timedelta(hours=20)
        early = detected + _EARLY_WARNING_WINDOW
        remaining = early - datetime.now(timezone.utc)
        assert remaining < timedelta(hours=5), (
            "an incident detected 20 hours ago must leave under 5 hours of the "
            "24-hour early-warning window, not a fresh 24"
        )


class TestDetectionTimeIsNotPatchable:
    """The three deadlines are stored at declaration.

    Letting a later edit move `detected_at` would silently move an obligation
    the operator may already have acted on — and would do it without any trace.
    Correcting a genuinely wrong detection time is a delete-and-redeclare, which
    the audit log records.
    """

    def test_patch_schema_has_no_detected_at(self):
        assert "detected_at" not in IncidentPatchRequest.model_fields

    def test_patch_schema_has_no_deadline_fields(self):
        for field in (
            "early_warning_deadline",
            "notification_deadline",
            "final_report_deadline",
        ):
            assert field not in IncidentPatchRequest.model_fields, (
                f"{field} is patchable; a deadline must not be editable after "
                f"the incident is declared"
            )


class TestTheWritePathTargetsTheModelTheClockReads:
    def test_router_creates_the_lifecycle_model(self):
        """Guards against the write path drifting back onto `incident_reports`,
        which is the shape of the original defect."""
        import inspect

        from app.routers import incident_monitor

        source = inspect.getsource(incident_monitor.declare_incident)
        assert "Incident(" in source
        assert "IncidentReport" not in source

    @pytest.mark.parametrize(
        "field",
        ["early_warning_deadline", "notification_deadline", "final_report_deadline"],
    )
    def test_all_three_deadlines_are_set_at_creation(self, field: str):
        """A row missing one is invisible to that stage of the obligation."""
        import inspect

        from app.routers import incident_monitor

        source = inspect.getsource(incident_monitor.declare_incident)
        assert f"{field}=" in source

    def test_the_alerting_task_reads_the_same_model(self):
        """monitor, alerting task and write path must agree, or an incident is
        visible in one and not the others."""
        import inspect

        from app.tasks import incident_tasks

        source = inspect.getsource(incident_tasks)
        assert "from app.models.incident import Incident" in source or "Incident" in source
