# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
"""The executive summary is rendered (not escaped) by the reports + UI, so the
SummaryGenerator MUST html-escape every DATA value it interpolates — otherwise a
finding/risk string with <script> injects into the report. The structural tags
stay raw so the summary still renders."""
from nis2scan.summary import BusinessRisk, SummaryGenerator, _esc


def test_esc_escapes_markup():
    assert _esc("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"
    assert _esc('"><img src=x>') == "&quot;&gt;&lt;img src=x&gt;"


class _Report:
    stats = {"analyzed_hosts": 1}


def test_build_html_escapes_injected_data_but_keeps_structure():
    gen = SummaryGenerator()
    metrics = {
        "status": "<script>x</script>",
        "score": 50,
        "total_findings": 1,
        "critical_count": 1,
        "high_count": 0,
    }
    risks = [
        BusinessRisk(
            name="<img src=x onerror=alert(1)>",
            impact="<b>boom</b>",
            probability="High",
            related_findings=[],
        )
    ]
    action_plan = [
        {
            "priority": "Immediate",
            "step": "<script>s</script>",
            "finding": "<i>f</i>",
            "target": "evil<svg>",
            "reference": 'NIS2"><script>',
        }
    ]

    out = gen._build_html(_Report(), risks, metrics, action_plan)

    # No LIVE injected tags survive...
    assert "<script>" not in out
    assert "<img" not in out
    assert "onerror=alert(1)>" not in out  # the live attribute form is gone
    # ...the data is present but escaped...
    assert "&lt;script&gt;" in out
    assert "&lt;img" in out
    # ...and the generator's own structural tags ARE rendered (not escaped).
    assert "<ul" in out and "<li" in out and "<strong>" in out
