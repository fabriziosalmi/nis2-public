# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Tests for the NIS2 Art. 23 incident deadline alerting logic.

Exercises _classify_alert() and _build_alert_payload() as pure
functions — no database, no Redis, no network required.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from app.tasks.incident_tasks import (
    WARN_HOURS_BEFORE,
    _CLOSED_STATUSES,
    _DEADLINES,
    _TTL_APPROACHING,
    _TTL_OVERDUE,
    _build_alert_payload,
    _classify_alert,
    _synthetic_email_channel,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _incident(title: str = "Test Incident", severity: str = "high") -> MagicMock:
    inc = MagicMock()
    inc.id = "00000000-0000-0000-0000-000000000001"
    inc.title = title
    inc.incident_type = "ransomware"
    inc.severity = severity
    inc.detected_at = _now() - timedelta(hours=20)
    return inc


# ---------------------------------------------------------------------------
# _classify_alert
# ---------------------------------------------------------------------------

class TestClassifyAlert:
    def test_well_before_deadline_returns_none(self) -> None:
        now = _now()
        deadline = now + timedelta(hours=WARN_HOURS_BEFORE + 1)
        assert _classify_alert(now, deadline) is None

    def test_exactly_at_warn_threshold_returns_approaching(self) -> None:
        now = _now()
        deadline = now + timedelta(hours=WARN_HOURS_BEFORE)
        assert _classify_alert(now, deadline) == "approaching"

    def test_within_warn_window_returns_approaching(self) -> None:
        now = _now()
        deadline = now + timedelta(hours=1)  # 1h < WARN_HOURS_BEFORE (2h)
        assert _classify_alert(now, deadline) == "approaching"

    def test_exactly_at_deadline_returns_overdue(self) -> None:
        now = _now()
        deadline = now  # exactly now = overdue (now >= deadline)
        assert _classify_alert(now, deadline) == "overdue"

    def test_past_deadline_returns_overdue(self) -> None:
        now = _now()
        deadline = now - timedelta(hours=5)
        assert _classify_alert(now, deadline) == "overdue"

    def test_1_second_before_deadline_returns_approaching(self) -> None:
        now = _now()
        deadline = now + timedelta(seconds=1)
        assert _classify_alert(now, deadline) == "approaching"


# ---------------------------------------------------------------------------
# _build_alert_payload
# ---------------------------------------------------------------------------

class TestBuildAlertPayload:
    def _make_payload(self, alert_type: str, hours_left: float = 1.0) -> dict:
        now = _now()
        if alert_type == "overdue":
            deadline = now - timedelta(hours=0.5)
        else:
            deadline = now + timedelta(hours=hours_left)
        return _build_alert_payload(
            incident=_incident(),
            now=now,
            deadline=deadline,
            label="Early Warning",
            article_ref="Art. 23.1 — 24h from detection",
            alert_type=alert_type,
        )

    def test_approaching_subject_contains_alert_keyword(self) -> None:
        payload = self._make_payload("approaching")
        assert "ALERT" in payload["subject"]
        assert "Early Warning" in payload["subject"]

    def test_overdue_subject_contains_overdue_keyword(self) -> None:
        payload = self._make_payload("overdue")
        assert "OVERDUE" in payload["subject"]

    def test_body_contains_article_ref(self) -> None:
        payload = self._make_payload("approaching")
        assert "Art. 23.1" in payload["body"]

    def test_body_contains_csirt_mention(self) -> None:
        payload = self._make_payload("overdue")
        assert "csirt" in payload["body"].lower()

    def test_payload_has_required_keys(self) -> None:
        payload = self._make_payload("approaching")
        required = {
            "subject", "body", "incident_id", "incident_title",
            "incident_severity", "deadline_label", "deadline_at",
            "alert_type", "article_ref",
        }
        assert required.issubset(set(payload.keys()))

    def test_alert_type_preserved_in_payload(self) -> None:
        for at in ("approaching", "overdue"):
            assert self._make_payload(at)["alert_type"] == at

    def test_overdue_body_mentions_overdue(self) -> None:
        payload = self._make_payload("overdue")
        assert "OVERDUE" in payload["body"]

    def test_approaching_body_mentions_minutes(self) -> None:
        payload = self._make_payload("approaching", hours_left=1.5)
        assert "minutes" in payload["body"]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class TestConstants:
    def test_warn_hours_before_is_positive(self) -> None:
        assert WARN_HOURS_BEFORE > 0

    def test_ttl_approaching_covers_warn_window(self) -> None:
        # TTL must exceed WARN_HOURS_BEFORE so one alert covers the window.
        assert _TTL_APPROACHING > WARN_HOURS_BEFORE * 3600

    def test_ttl_overdue_is_at_least_one_day(self) -> None:
        assert _TTL_OVERDUE >= 86400

    def test_closed_statuses_includes_closed_and_recovered(self) -> None:
        assert "closed" in _CLOSED_STATUSES
        assert "recovered" in _CLOSED_STATUSES
        assert "eradicated" in _CLOSED_STATUSES
        assert "detected" not in _CLOSED_STATUSES

    def test_deadlines_tuple_covers_all_three_art23_steps(self) -> None:
        deadline_fields = {d[0] for d in _DEADLINES}
        assert "early_warning_deadline" in deadline_fields
        assert "notification_deadline" in deadline_fields
        assert "final_report_deadline" in deadline_fields

    def test_deadlines_sent_fields_are_consistent(self) -> None:
        # Each deadline must have a matching *_sent_at field.
        for deadline_field, sent_field, *_ in _DEADLINES:
            assert sent_field.endswith("_sent_at"), f"{sent_field} should end with _sent_at"
            assert deadline_field.endswith("_deadline"), f"{deadline_field} should end with _deadline"


# ---------------------------------------------------------------------------
# Synthetic email channel fallback
# ---------------------------------------------------------------------------

class TestSyntheticEmailChannel:
    def test_channel_type_is_email(self) -> None:
        ch = _synthetic_email_channel("admin@example.com")
        assert ch.channel_type == "email"

    def test_config_contains_email(self) -> None:
        ch = _synthetic_email_channel("admin@example.com")
        assert ch.config["email"] == "admin@example.com"

    def test_name_contains_email(self) -> None:
        ch = _synthetic_email_channel("admin@example.com")
        assert "admin@example.com" in ch.name
