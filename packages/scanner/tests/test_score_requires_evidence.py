# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""A compliance score is a claim, and a claim needs evidence.

The engine returned 100 when no host was alive. Combined with the API rebuilding
the scanner configuration from a JSONB column using .get() with a default for
every key, that made losing a scan's own configuration indistinguishable from
perfect compliance: an empty config_snapshot produced no targets, no target
produced no live host, and no live host produced a score of 100 which was then
committed as a completed scan, rendered on the dashboard, folded into the Art. 21
matrix and printed in the archival PDF/A dossier.

The direction matters more than the number. Of all the ways this product can be
wrong, reporting compliance that was never measured is the worst.

Two distinct causes are now separated, because the operator's next action
differs: no targets at all means the assets are wrong, while targets that did not
answer means the network or the hosts are.
"""

from __future__ import annotations

from nis2scan.compliance import ComplianceEngine
from nis2scan.config import Config, Targets
from nis2scan.scanner import ScanResult


def _engine() -> ComplianceEngine:
    return ComplianceEngine(Config(targets=Targets(ip_ranges=["203.0.113.1"])))


class TestNoScoreWithoutAnAssessedHost:
    def test_an_empty_scan_scores_nothing_rather_than_a_hundred(self):
        """The whole defect. This used to return 100."""
        report = _engine().evaluate([])
        assert report.total_score is None

    def test_it_says_why_there_is_no_score(self):
        report = _engine().evaluate([])
        assert report.not_assessed_reason
        assert "no targets" in report.not_assessed_reason.lower()

    def test_targets_that_did_not_answer_are_a_different_reason(self):
        """Both cases used to score 100; they call for different actions, so
        they must not collapse into one message."""
        dead = ScanResult(target="203.0.113.1", ip="203.0.113.1", is_alive=False)
        report = _engine().evaluate([dead])
        assert report.total_score is None
        assert "responded" in report.not_assessed_reason

    def test_the_two_reasons_are_distinguishable(self):
        empty = _engine().evaluate([])
        dead = _engine().evaluate(
            [ScanResult(target="203.0.113.1", ip="203.0.113.1", is_alive=False)]
        )
        assert empty.not_assessed_reason != dead.not_assessed_reason

    def test_one_live_clean_host_still_scores_a_hundred(self):
        """The fix must not suppress a legitimate perfect score - a host that
        was assessed and had no findings is exactly what 100 is for."""
        alive = ScanResult(target="203.0.113.1", ip="203.0.113.1", is_alive=True)
        report = _engine().evaluate([alive])
        assert report.total_score == 100
        assert report.not_assessed_reason == ""


class TestTheConsumersSurviveAnAbsentScore:
    def test_the_executive_summary_reports_not_assessed(self):
        """Comparing None against 50 raised TypeError once the engine stopped
        inventing a number, so the summary had to learn the third state."""
        report = _engine().evaluate([])
        assert report.executive_summary

    def test_the_prometheus_gauge_is_left_alone(self):
        """Setting it to 0 would read as total non-compliance and 100 as
        perfect; a stale sample is the honest signal."""
        import inspect

        from nis2scan import exporter

        source = inspect.getsource(exporter)
        assert "if report.total_score is not None:" in source

    def test_the_console_report_does_not_exit_early(self):
        """An absent score must not suppress the host statistics - those counts
        are exactly what explains why there is no score."""
        import inspect

        from nis2scan.reporter import Reporter

        source = inspect.getsource(Reporter.print_to_console)
        assert "not assessed" in source
        assert "return" not in source.split("Scan Statistics")[0]
