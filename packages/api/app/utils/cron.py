# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
v2.4.26 audit: validate cron expressions at create/update time.

Pre-2.4.26 the only check on `POST /api/v1/schedules` was that the cron
string had 5 whitespace-separated fields. Any garbage in those fields
("99 99 99 99 99", "a b c d e") was accepted by the API; the schedule
silently never fired because `app.tasks.scan_tasks._should_run` swallows
parse exceptions and returns False. The user saw no error at create
time, no error in the schedules list, and no scans firing — a
particularly painful "looks valid, doesn't work" failure mode.

Why a hand-rolled parser instead of `croniter`:
  - We already ship a parser in `_should_run` (scan_tasks.py); adding a
    second one would let validation drift away from execution. This
    module is the single source of truth.
  - `croniter` introduces a runtime dependency for one validator —
    weight-bearing in CI and Docker images — for code we can fit in
    ~80 lines.
  - Vixie cron syntax we accept is a strict subset (no L, W, # or @
    keywords); rolling our own keeps the surface area exactly what
    `_should_run` understands. If a user submits `@daily`, we want a
    400 with a hint, not silent acceptance plus runtime parse failure.

What's accepted, per field:
  - `*`                  every value
  - `N`                  exact value
  - `N-M`                inclusive range, N <= M
  - `N,M,K`              list of values / ranges
  - `* / S` or `N-M / S` step (must be positive integer)

Field ranges:
  - minute   0-59
  - hour     0-23
  - dom      1-31  (day-of-month)
  - month    1-12
  - dow      0-7   (Sunday is both 0 AND 7, accepted by both forms)

Anything else (letters, day names, @keywords, special chars) is rejected
with a 400-friendly error message that points at the offending field.
"""
from __future__ import annotations


_FIELD_RANGES: list[tuple[str, int, int]] = [
    ("minute", 0, 59),
    ("hour", 0, 23),
    ("day-of-month", 1, 31),
    ("month", 1, 12),
    ("day-of-week", 0, 7),
]


class CronValidationError(ValueError):
    """Raised when a cron expression cannot be parsed.

    Inherits from ValueError so callers can catch either; the schedules
    router converts it to an HTTP 400 with the message preserved.
    """


def _parse_int(token: str, lo: int, hi: int, field_name: str) -> int:
    try:
        value = int(token)
    except ValueError:
        raise CronValidationError(
            f"{field_name}: '{token}' is not a number"
        )
    if value < lo or value > hi:
        raise CronValidationError(
            f"{field_name}: {value} is outside the allowed range {lo}-{hi}"
        )
    return value


def _validate_field(field: str, lo: int, hi: int, field_name: str) -> None:
    """Validate a single cron field token (one of 5 in the expression).

    Recursive on the comma-separated list form so `1,3-5,*/10` is a
    single call to `_validate_field` that delegates to itself per
    sub-token. This mirrors the matcher in `scan_tasks._should_run`
    so the two stay in lockstep.
    """
    if not field:
        raise CronValidationError(f"{field_name}: empty field not allowed")

    # Comma list: validate each sub-expression independently. We catch
    # `,,` (empty sub-tokens) at this layer rather than below so the
    # error message points at the list, not at the empty piece.
    if "," in field:
        sub_tokens = field.split(",")
        if any(not s for s in sub_tokens):
            raise CronValidationError(
                f"{field_name}: empty list element in '{field}'"
            )
        for sub in sub_tokens:
            _validate_field(sub.strip(), lo, hi, field_name)
        return

    # Step form: `<base>/<step>`. The base may itself be `*`, a single
    # value, or a range — each handled by the recursion below after we
    # peel off the step.
    if "/" in field:
        try:
            base, step_raw = field.split("/", 1)
        except ValueError:
            # Should be unreachable given `/` in field, but defensive.
            raise CronValidationError(f"{field_name}: malformed step '{field}'")
        if not base or not step_raw:
            raise CronValidationError(
                f"{field_name}: '{field}' has an empty base or step"
            )
        step = _parse_int(step_raw, 1, max(hi, 1), field_name)
        if step <= 0:
            raise CronValidationError(
                f"{field_name}: step must be a positive integer, got {step}"
            )
        # Recurse on the base (which is itself a valid sub-form).
        _validate_field(base, lo, hi, field_name)
        return

    if field == "*":
        return

    # Range form: `<lo>-<hi>`, both ends within [lo, hi], lo <= hi.
    if "-" in field:
        try:
            low_raw, high_raw = field.split("-", 1)
        except ValueError:
            raise CronValidationError(f"{field_name}: malformed range '{field}'")
        low = _parse_int(low_raw, lo, hi, field_name)
        high = _parse_int(high_raw, lo, hi, field_name)
        if low > high:
            raise CronValidationError(
                f"{field_name}: range start {low} is greater than end {high}"
            )
        return

    # Plain single value.
    _parse_int(field, lo, hi, field_name)


def validate_cron(expression: str) -> None:
    """Validate a 5-field Vixie-style cron expression.

    Raises `CronValidationError` (a `ValueError` subclass) on any
    parsing or range error. Returns None on success.

    Whitespace is normalised: leading/trailing spaces are stripped, and
    runs of internal whitespace collapse to a single split — `"  0  9
    *  *  1-5  "` is treated the same as `"0 9 * * 1-5"`.
    """
    if expression is None:
        raise CronValidationError("cron expression is required")
    parts = expression.strip().split()
    if len(parts) != 5:
        raise CronValidationError(
            f"cron expression must have exactly 5 fields "
            f"(minute hour day-of-month month day-of-week); got {len(parts)}"
        )
    for token, (field_name, lo, hi) in zip(parts, _FIELD_RANGES):
        _validate_field(token, lo, hi, field_name)
