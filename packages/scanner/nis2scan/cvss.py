# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""CVSS v3.1 base score, computed from the vector.

Findings carried a hand-picked `cvss_base_score` — every exposed database port
was 9.1, every weak TLS version 7.5 — and only 18 of the 32 carried a vector at
all, four of them scoring 0.0. Those numbers reach the archival PDF/A dossier,
the CSV export and the JSON API under a column headed "CVSS Score".

A CVSS base score is, by the specification, a function of its vector. A number
labelled CVSS that was chosen by hand is not a CVSS score, and it is the single
most attackable thing in the report: "on what basis is this a 7.5?" has no good
answer when the vector is absent, and a worse one when the vector is present and
disagrees with the number printed beside it.

So the score is derived here, and a finding with no vector publishes no CVSS
number at all — an empty cell an auditor can ask about beats a number that
cannot be defended.

Implements the arithmetic in the CVSS v3.1 specification (FIRST.org),
section 8.1. Base metrics only: temporal and environmental metrics describe a
particular deployment at a particular moment, which an external scan cannot
observe and must not invent.
"""

from __future__ import annotations

import math
import re
from typing import Optional

# Specification weights, section 8.1. Privileges Required depends on Scope,
# which is why it is two tables.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

_VECTOR_RE = re.compile(r"^CVSS:3\.[01]/(.+)$")
_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


class InvalidVector(ValueError):
    """The vector is absent, malformed, or missing a required base metric."""


def parse_vector(vector: str) -> dict[str, str]:
    """Split a CVSS v3.x vector string into its base metrics."""
    if not vector:
        raise InvalidVector("empty vector")
    match = _VECTOR_RE.match(vector.strip())
    if not match:
        raise InvalidVector(f"not a CVSS v3.x vector: {vector!r}")

    metrics: dict[str, str] = {}
    for part in match.group(1).split("/"):
        key, _, value = part.partition(":")
        if key and value:
            metrics[key.strip().upper()] = value.strip().upper()

    missing = [m for m in _REQUIRED if m not in metrics]
    if missing:
        raise InvalidVector(f"vector is missing required metrics: {', '.join(missing)}")
    return metrics


def _roundup(value: float) -> float:
    """The specification's Roundup: the smallest 1-decimal number >= value.

    Not Python's round(). The spec defines this in integer arithmetic precisely
    to avoid binary floating-point surprises, and the difference is visible: a
    naive round() turns 8.05 into 8.0 where CVSS requires 8.1.
    """
    integer = int(round(value * 100000))
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def base_score(vector: str) -> float:
    """Compute the CVSS v3.1 base score for `vector`.

    Raises InvalidVector rather than returning a default. A finding whose vector
    cannot be parsed must publish no score — inventing one is how the hand-picked
    numbers got there in the first place.
    """
    m = parse_vector(vector)
    scope_changed = m["S"] == "C"

    try:
        iss = 1 - ((1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]]))
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss

        pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED
        exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr_table[m["PR"]] * _UI[m["UI"]]
    except KeyError as exc:
        raise InvalidVector(f"unknown metric value: {exc}") from exc

    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def score_for(vector: Optional[str]) -> Optional[float]:
    """Best-effort score: None when there is no defensible vector.

    This is what the finding pipeline calls. Returning None is the point — the
    report then prints nothing rather than a number nobody can justify.
    """
    if not vector:
        return None
    try:
        return base_score(vector)
    except InvalidVector:
        return None


def severity_band(score: Optional[float]) -> str:
    """The qualitative rating in section 5 of the specification."""
    if score is None:
        return "NONE"
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"
