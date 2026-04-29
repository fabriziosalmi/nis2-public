# Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
v2.4.26 unit tests for `app.utils.cron`.

Standalone — no DB / no FastAPI / no Celery. The validator is a pure
function and these tests pin every accepted form (per Vixie cron) and
the most common rejection cases. The corresponding *execution* logic
in `app.tasks.scan_tasks._should_run` should accept exactly the same
forms; if a future change to either side widens or narrows the surface,
adjust both files together.
"""
from __future__ import annotations

import pytest

from app.utils.cron import CronValidationError, validate_cron


class TestAccepted:
    """Each test is one Vixie-cron form documented in the module docstring.

    None of these should raise.
    """

    @pytest.mark.parametrize(
        "expr",
        [
            "* * * * *",                    # every minute
            "0 9 * * 1-5",                  # weekdays 9am
            "*/5 * * * *",                  # every 5 minutes
            "0 0 1 * *",                    # midnight first of month
            "0 0 1 1 *",                    # midnight Jan 1
            "30 14 * * 0",                  # Sunday 14:30 (dow=0)
            "30 14 * * 7",                  # Sunday 14:30 (dow=7 — both forms)
            "0,15,30,45 * * * *",           # quarter-hourly
            "0 9-17 * * 1-5",               # business hours
            "0 9-17/2 * * 1-5",             # business hours, every 2h
            "1-10/2 * * * *",               # ranged step
            "0 0 31 12 *",                  # Dec 31 midnight (dom=31 boundary)
            "59 23 * * *",                  # last minute of day
            "0 0 * * *",                    # daily midnight
            "  0  9  *  *  1-5  ",          # whitespace tolerance
        ],
    )
    def test_accepted(self, expr: str) -> None:
        # Returns None on success; the lack of exception is the assertion.
        assert validate_cron(expr) is None


class TestFieldCount:
    @pytest.mark.parametrize("expr", ["", " ", "* * * *", "* * * * * *"])
    def test_wrong_field_count(self, expr: str) -> None:
        with pytest.raises(CronValidationError, match="exactly 5 fields"):
            validate_cron(expr)

    def test_none(self) -> None:
        with pytest.raises(CronValidationError, match="required"):
            validate_cron(None)  # type: ignore[arg-type]


class TestRangeChecks:
    """The agent-flagged regression: pre-2.4.26 `99 99 99 99 99` was accepted."""

    def test_rejects_minute_too_high(self) -> None:
        with pytest.raises(CronValidationError, match="minute"):
            validate_cron("60 0 1 1 0")

    def test_rejects_minute_negative_via_letters(self) -> None:
        with pytest.raises(CronValidationError, match="minute.*not a number"):
            validate_cron("a 0 1 1 0")

    def test_rejects_hour_too_high(self) -> None:
        with pytest.raises(CronValidationError, match="hour"):
            validate_cron("0 24 1 1 0")

    def test_rejects_dom_zero(self) -> None:
        # day-of-month is 1-indexed; 0 is invalid.
        with pytest.raises(CronValidationError, match="day-of-month"):
            validate_cron("0 0 0 1 0")

    def test_rejects_dom_too_high(self) -> None:
        with pytest.raises(CronValidationError, match="day-of-month"):
            validate_cron("0 0 32 1 0")

    def test_rejects_month_zero(self) -> None:
        with pytest.raises(CronValidationError, match="month"):
            validate_cron("0 0 1 0 0")

    def test_rejects_month_too_high(self) -> None:
        with pytest.raises(CronValidationError, match="month"):
            validate_cron("0 0 1 13 0")

    def test_rejects_dow_too_high(self) -> None:
        with pytest.raises(CronValidationError, match="day-of-week"):
            validate_cron("0 0 1 1 8")

    def test_rejects_audit_smoking_gun(self) -> None:
        # The exact garbage the agent flagged. Pre-2.4.26 the schedules
        # API accepted this and the schedule silently never fired.
        with pytest.raises(CronValidationError):
            validate_cron("99 99 99 99 99")

    def test_rejects_letters_only(self) -> None:
        # Same agent-flagged failure mode: legible-looking gibberish.
        with pytest.raises(CronValidationError):
            validate_cron("a b c d e")


class TestRangeForm:
    def test_inverted_range_rejected(self) -> None:
        # 17-9 is invalid: start > end. A naive parser would silently
        # generate an empty match-set and the schedule would never fire.
        with pytest.raises(CronValidationError, match="range start.*greater than"):
            validate_cron("0 17-9 * * *")

    def test_range_endpoint_at_field_max_accepted(self) -> None:
        validate_cron("0 0-23 * * *")   # full hour range
        validate_cron("0-59 * * * *")   # full minute range

    def test_range_endpoint_one_past_field_max_rejected(self) -> None:
        with pytest.raises(CronValidationError, match="hour"):
            validate_cron("0 0-24 * * *")


class TestStepForm:
    def test_zero_step_rejected(self) -> None:
        with pytest.raises(CronValidationError):
            validate_cron("*/0 * * * *")

    def test_negative_step_rejected(self) -> None:
        # `*/-5` will fail at the int parse with "outside the allowed
        # range" because the parser bounds steps to [1, hi].
        with pytest.raises(CronValidationError):
            validate_cron("*/-5 * * * *")

    def test_step_with_explicit_base(self) -> None:
        validate_cron("5/10 * * * *")   # every 10 starting at minute 5

    def test_step_with_range_base(self) -> None:
        validate_cron("0-30/5 * * * *")

    def test_empty_base_rejected(self) -> None:
        with pytest.raises(CronValidationError, match="empty base"):
            validate_cron("/5 * * * *")

    def test_empty_step_rejected(self) -> None:
        with pytest.raises(CronValidationError, match="empty base or step"):
            validate_cron("*/  * * * *")


class TestListForm:
    def test_simple_list(self) -> None:
        validate_cron("0,15,30,45 * * * *")

    def test_list_with_ranges_and_steps(self) -> None:
        validate_cron("0,15-20,30/5 * * * *")

    def test_empty_list_element_rejected(self) -> None:
        with pytest.raises(CronValidationError, match="empty list element"):
            validate_cron("0,,30 * * * *")

    def test_list_value_out_of_range_rejected(self) -> None:
        # Catch the case where ONE element of a list is out of range
        # (the others are fine). Prevents a partial-validation regression.
        with pytest.raises(CronValidationError, match="minute"):
            validate_cron("0,30,99 * * * *")


class TestVixieKeywordsRejected:
    """We deliberately do NOT accept @-keywords (@daily, @hourly, @reboot)
    or day names (MON, TUE) because the executor in `_should_run` doesn't
    handle them either. Silent acceptance + runtime parse failure is the
    exact failure mode this patch closes."""

    @pytest.mark.parametrize("expr", ["@daily", "@hourly", "@reboot"])
    def test_keyword_rejected(self, expr: str) -> None:
        with pytest.raises(CronValidationError):
            validate_cron(expr)

    def test_day_name_rejected(self) -> None:
        with pytest.raises(CronValidationError):
            validate_cron("0 0 * * MON")
