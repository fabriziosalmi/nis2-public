# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""Art. 23 obligations: the right deadline, and a way to discharge it.

Three defects, all in the module the product is sold on.

1. The final report was due `detected_at + 30 days`. Art. 23(4)(d) requires it
   "not later than one month after the submission of the incident notification
   referred to in point (b)" — the 72-hour notification. Every incident was
   therefore reported as due three days early, and the breach alert fired while
   the operator was still inside the legal window. `routers/acn.py` had already
   been corrected; `routers/incident_monitor.py`, the path that actually writes
   the row the monitor and the dashboard read, had not.

2. `early_warning_sent_at`, `notification_sent_at` and `final_report_sent_at`
   were read by the Celery task, by the response builder and by the dashboard —
   and written by nothing. The alerting could not be switched off by doing the
   thing it was alerting about: an operator who filed the Early Warning on time
   kept receiving breach alerts for it, daily, with no escape but closing or
   deleting the incident.

3. The CSIRT "Red Button" composed an Early Warning document and persisted
   nothing. No `incidents` row, so no countdown, no 24-hour alert, nothing in
   the dossier. The operator pressed the emergency button in the worst hour of
   their year, received a file, and the deadline monitor never learned the
   incident existed.
"""

from __future__ import annotations

import inspect
from datetime import datetime, timedelta, timezone

import pytest

from app.routers.incident_monitor import (
    _FINAL_REPORT_WINDOW,
    _NOTIFICATION_WINDOW,
    RecordSubmissionRequest,
    final_report_deadline_for,
)

DETECTED = datetime(2026, 3, 1, 8, 0, tzinfo=timezone.utc)


class TestTheFinalReportAnchor:
    def test_it_runs_from_the_notification_not_from_detection(self):
        """The whole defect in one assertion."""
        assert final_report_deadline_for(DETECTED) == (
            DETECTED + _NOTIFICATION_WINDOW + _FINAL_REPORT_WINDOW
        )
        assert final_report_deadline_for(DETECTED) != DETECTED + _FINAL_REPORT_WINDOW

    def test_the_old_formula_was_three_days_early(self):
        """Not a rounding error: three days of an obligation, and three days of
        breach alerts fired inside the legal window."""
        old = DETECTED + _FINAL_REPORT_WINDOW
        assert final_report_deadline_for(DETECTED) - old == timedelta(hours=72)

    def test_an_actual_submission_becomes_the_anchor(self):
        """Art. 23(4)(d) anchors on the submission, not on its deadline. Filing
        the notification early therefore brings the final report forward — the
        directive is stricter than the platform used to be, in both directions."""
        submitted = DETECTED + timedelta(hours=40)
        assert final_report_deadline_for(DETECTED, submitted) == (
            submitted + _FINAL_REPORT_WINDOW
        )

    def test_before_submission_the_latest_lawful_anchor_is_used(self):
        """Until the notification is filed there is no anchor, so the 72-hour
        deadline stands in for it. That is the latest the anchor can legally be,
        which makes the answer conservative rather than optimistic."""
        assert final_report_deadline_for(DETECTED) >= final_report_deadline_for(
            DETECTED, DETECTED + timedelta(hours=1)
        )

    def test_the_alert_text_no_longer_states_the_wrong_anchor(self):
        """The operator reads this string in the email. It said "1 month from
        detection", which is both the wrong rule and a plausible-looking one."""
        from app.tasks import incident_tasks

        source = inspect.getsource(incident_tasks)
        assert "1 month from detection" not in source
        assert "Art. 23(4)(d)" in source


class TestRecordingThatAnObligationWasDischarged:
    """There was no way to. The fields existed and nothing wrote them."""

    def test_the_endpoint_exists(self):
        from app.routers import incident_monitor

        assert hasattr(incident_monitor, "record_submission")

    @pytest.mark.parametrize(
        "obligation", ["early_warning", "notification", "final_report"]
    )
    def test_every_obligation_can_be_recorded(self, obligation: str):
        from app.routers.incident_monitor import _OBLIGATIONS

        assert obligation in _OBLIGATIONS
        sent_field, deadline_field = _OBLIGATIONS[obligation]
        assert sent_field.endswith("_sent_at")
        assert deadline_field.endswith("_deadline")

    def test_something_now_writes_the_sent_fields(self):
        """The regression that matters. Every one of these was read in three
        places and written in none."""
        from app.routers import incident_monitor

        source = inspect.getsource(incident_monitor.record_submission)
        assert "setattr(incident, sent_field" in source

    def test_recording_the_notification_re_anchors_the_final_report(self):
        from app.routers import incident_monitor

        source = inspect.getsource(incident_monitor.record_submission)
        assert "final_report_deadline_for" in source
        assert "final_report_sent_at is None" in source, (
            "re-anchoring a final report that has already been filed would "
            "rewrite history"
        )

    def test_a_future_submission_is_refused(self):
        """It would silently suppress the alerting until that date arrived."""
        from app.routers import incident_monitor

        source = inspect.getsource(incident_monitor.record_submission)
        assert "cannot be in the future" in source

    def test_a_submission_before_detection_is_refused(self):
        from app.routers import incident_monitor

        source = inspect.getsource(incident_monitor.record_submission)
        assert "cannot precede the recorded detection time" in source

    def test_recording_is_not_a_viewer_action(self):
        from app.routers import incident_monitor

        module = inspect.getsource(incident_monitor)
        idx = module.index("async def record_submission")
        decorator = module[max(0, idx - 400) : idx]
        assert 'require_role("admin", "auditor")' in decorator

    def test_the_csirt_reference_can_be_recorded_with_it(self):
        """The reference CSIRT Italia returns is the only evidence tying the
        row to the actual filing."""
        assert "csirt_reference_id" in RecordSubmissionRequest.model_fields

    def test_submitted_at_defaults_to_now_but_is_settable(self):
        """The submission usually happened before someone recorded it, and the
        recorded time is what an auditor reads."""
        field = RecordSubmissionRequest.model_fields["submitted_at"]
        assert not field.is_required()


class TestTheRedButtonStartsTheClock:
    def test_it_declares_an_incident(self):
        """It produced a document and persisted nothing: the operator held an
        Early Warning payload and the monitor knew of no incident."""
        from app.routers import acn

        source = inspect.getsource(acn.csirt_emergency_payload)
        assert "Incident(" in source
        assert "db.add(incident)" in source

    def test_the_deadlines_it_stores_use_the_shared_arithmetic(self):
        """Two copies of the Art. 23 windows is how they came to disagree in
        the first place."""
        from app.routers import acn

        source = inspect.getsource(acn.csirt_emergency_payload)
        assert "final_report_deadline_for(detected)" in source
        assert "timedelta(hours=24)" not in source
        assert "timedelta(days=30)" not in source

    def test_the_payload_carries_the_incident_id(self):
        """Without it the document cannot be traced back to the record the
        deadline monitor watches."""
        from app.routers import acn

        source = inspect.getsource(acn.csirt_emergency_payload)
        assert '"incident_id"' in source

    def test_pressing_it_is_not_a_viewer_action(self):
        """It writes an incident now, so it is gated like the write path it
        shares — a viewer could previously invoke it, which mattered less when
        it persisted nothing."""
        from app.routers import acn

        module = inspect.getsource(acn)
        idx = module.index("async def csirt_emergency_payload")
        decorator = module[max(0, idx - 400) : idx]
        assert 'require_role("admin", "auditor")' in decorator

    def test_it_tells_the_operator_how_to_stop_the_alerts(self):
        from app.routers import acn

        source = inspect.getsource(acn.csirt_emergency_payload)
        assert "submissions" in source
