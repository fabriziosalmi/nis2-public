# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""A legal check that could not run is not three violations.

The Italian checks - VAT number, privacy policy, cookie banner - are performed
through a headless browser. When the browser could not be launched, the checker
logged an error and returned an empty dict; the scanner assigned that dict
unconditionally to `result['legal']`; and the compliance engine's guard,
`if 'legal' in http_data`, was satisfied by it. It then tested
`italian.get('piva_found')`, found the key absent, and raised a finding stating
the VAT number was missing - and the same for the other two.

So a scanner host where `playwright install` had never been run accused every
Italian business it scanned of three consumer-law and GDPR breaches that were
never tested for. The operator saw a log line; the customer saw the findings in
the dossier.
"""

from __future__ import annotations

import inspect

from nis2scan.compliance import ComplianceEngine
from nis2scan.config import Config, Targets
from nis2scan.scanner import ScanResult


def _host_with_legal(legal: dict) -> ScanResult:
    host = ScanResult(target="example.it", ip="203.0.113.9", is_alive=True)
    host.open_ports = [443]
    host.http_info = {443: {"status": 200, "legal": legal}}
    return host


def _findings(host: ScanResult):
    engine = ComplianceEngine(Config(targets=Targets(domains=["example.it"])))
    return engine.evaluate([host]).findings


class TestAnUnavailableCheckIsNotAViolation:
    def test_the_browser_failure_returns_an_explicit_marker(self):
        """Returning {} is what let the absence read as a negative answer."""
        from nis2scan.legal import LegalChecker

        source = inspect.getsource(LegalChecker)
        assert '"unavailable": True' in source

    def test_no_piva_finding_is_raised_when_the_check_did_not_run(self):
        """The regression in one assertion."""
        host = _host_with_legal({"unavailable": True, "unavailable_reason": "no browser"})
        messages = [f.message for f in _findings(host)]
        assert not any("P.IVA" in m for m in messages)

    def test_no_privacy_or_cookie_finding_either(self):
        host = _host_with_legal({"unavailable": True, "unavailable_reason": "no browser"})
        messages = [f.message for f in _findings(host)]
        assert not any("Privacy Policy" in m for m in messages)
        assert not any("Cookie Consent" in m for m in messages)

    def test_the_gap_is_reported_rather_than_hidden(self):
        """Silence would be the other wrong answer: the operator must learn the
        check did not run, and it belongs in the report, not only in a log."""
        host = _host_with_legal({"unavailable": True, "unavailable_reason": "no browser"})
        gap = [f for f in _findings(host) if "not assessed" in f.message]
        assert gap and gap[0].severity == "INFO"

    def test_the_reason_reaches_the_report(self):
        host = _host_with_legal({
            "unavailable": True,
            "unavailable_reason": "Run `playwright install` on the scanner host.",
        })
        gap = [f for f in _findings(host) if "not assessed" in f.message]
        assert "playwright install" in gap[0].rationale

    def test_a_genuine_absence_is_still_reported(self):
        """The check must keep working when it did run: a page that really has
        no VAT number still produces the finding."""
        host = _host_with_legal({"italian_compliance": {"piva_found": False}})
        messages = [f.message for f in _findings(host)]
        assert any("P.IVA" in m for m in messages)
