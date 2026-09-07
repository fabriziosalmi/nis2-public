# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""Which hosts get the Italian legal checks — testing the shipped function.

This replaces test_scanner_logic.py, which was a tautology: it defined its own
copy of `should_check_legal` and its own copy of the DMARC parsing INSIDE the
test file and asserted against those. It imported neither from the scanner, so
it exercised nothing that shipped, and a refactor that broke `check_http` would
have left it green.

The two copies had already diverged. The test asserted
`"v=DMARC1" in txt_val`; the scanner does `txt_val.startswith('v=DMARC1')`. A
record with a leading space would satisfy the test and be rejected by the code —
the test was not merely useless, it described different behaviour.

The heuristic is now a module-level function, so these import it.
"""

from __future__ import annotations

import pytest

from nis2scan.scanner import should_run_legal_checks


class TestCommercialSitesAreChecked:
    @pytest.mark.parametrize("host", ["example.com", "azienda.it", "shop.de"])
    def test_apex_domains(self, host: str):
        assert should_run_legal_checks(host) is True

    @pytest.mark.parametrize("host", ["www.example.com", "www.azienda.it"])
    def test_www_hosts(self, host: str):
        assert should_run_legal_checks(host) is True

    @pytest.mark.parametrize("host", ["google.co.uk", "example.com.it", "shop.co.jp"])
    def test_two_level_public_suffixes(self, host: str):
        assert should_run_legal_checks(host) is True


class TestInfrastructureHostsAreSkipped:
    """Running Playwright against every host would be slow, and would report a
    missing privacy policy on an SMTP endpoint."""

    @pytest.mark.parametrize("host", ["192.168.1.1", "8.8.8.8", "203.0.113.7"])
    def test_bare_ipv4_is_not_a_commercial_website(self, host: str):
        assert should_run_legal_checks(host) is False

    @pytest.mark.parametrize("host", ["::1", "2001:db8::1"])
    def test_bare_ipv6_is_not_a_commercial_website(self, host: str):
        assert should_run_legal_checks(host) is False

    @pytest.mark.parametrize(
        "host", ["mail.example.com", "api.example.com", "staging.example.com"]
    )
    def test_service_subdomains(self, host: str):
        assert should_run_legal_checks(host) is False

    def test_deep_subdomains(self):
        assert should_run_legal_checks("api.test.example.com") is False

    def test_a_three_label_host_is_not_a_public_suffix_by_accident(self):
        """`sub.domain.com` has three labels like `example.co.uk`, but `domain`
        is longer than three characters, so the suffix heuristic must not fire."""
        assert should_run_legal_checks("sub.domain.com") is False


class TestTheHeuristicIsImportedNotReimplemented:
    def test_it_lives_in_the_scanner_module(self):
        """The point of this file. The previous test defined its own copy, so it
        could not fail when the scanner changed."""
        import inspect

        from nis2scan import scanner

        assert inspect.getmodule(should_run_legal_checks) is scanner

    def test_check_http_calls_it(self):
        """Structural: extracting a function and then not calling it would leave
        these tests passing while the scan behaved differently."""
        import inspect

        from nis2scan.scanner import Scanner

        assert "should_run_legal_checks(host_header)" in inspect.getsource(Scanner.check_http)
