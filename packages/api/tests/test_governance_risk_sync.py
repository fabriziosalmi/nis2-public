# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Tests for the scanner → governance risk signal bridge.

Covers _category_to_subparagraphs() and the sync-risk status escalation
rules without standing up a database or FastAPI app.
"""
from __future__ import annotations


from app.routers.governance import (
    CATEGORY_SUBPARAGRAPH_MAP,
    _category_to_subparagraphs,
    _HIGH_RISK_SEVERITIES,
    _RESOLVED_STATUSES,
)


class TestCategoryToSubparagraphs:
    """Pin the category → subparagraph mapping logic."""

    def test_tls_maps_to_cryptography_and_risk(self) -> None:
        result = _category_to_subparagraphs("tls_weak_cipher")
        assert "21.2.h" in result   # cryptography
        assert "21.2.a" in result   # catch-all risk analysis

    def test_ssl_maps_to_cryptography(self) -> None:
        result = _category_to_subparagraphs("ssl_expired_cert")
        assert "21.2.h" in result

    def test_certificate_maps_to_cryptography(self) -> None:
        result = _category_to_subparagraphs("certificate_expiry")
        assert "21.2.h" in result

    def test_port_maps_to_acquisition(self) -> None:
        result = _category_to_subparagraphs("port_open_rdp")
        assert "21.2.e" in result

    def test_dns_maps_to_acquisition(self) -> None:
        result = _category_to_subparagraphs("dns_missing_spf")
        assert "21.2.e" in result

    def test_secret_maps_to_access_control(self) -> None:
        result = _category_to_subparagraphs("secret_api_key_exposed")
        assert "21.2.i" in result

    def test_mfa_maps_to_authentication(self) -> None:
        result = _category_to_subparagraphs("mfa_not_enforced")
        assert "21.2.j" in result

    def test_auth_maps_to_authentication(self) -> None:
        result = _category_to_subparagraphs("auth_weak_password")
        assert "21.2.j" in result

    def test_vulnerability_maps_to_effectiveness(self) -> None:
        result = _category_to_subparagraphs("vulnerability_cve_2024")
        assert "21.2.f" in result

    def test_backup_maps_to_continuity(self) -> None:
        result = _category_to_subparagraphs("backup_missing")
        assert "21.2.c" in result

    def test_incident_maps_to_handling(self) -> None:
        result = _category_to_subparagraphs("incident_response_missing")
        assert "21.2.b" in result

    def test_vendor_maps_to_supply_chain(self) -> None:
        result = _category_to_subparagraphs("vendor_no_sla")
        assert "21.2.d" in result

    def test_unknown_category_only_maps_to_risk_analysis(self) -> None:
        # An unknown category still lands in the catch-all 21.2.a.
        result = _category_to_subparagraphs("some_unknown_category")
        assert result == ["21.2.a"]

    def test_empty_category_only_maps_to_risk_analysis(self) -> None:
        result = _category_to_subparagraphs("")
        assert result == ["21.2.a"]

    def test_no_duplicates_in_result(self) -> None:
        # A category matching multiple prefixes must still deduplicate.
        result = _category_to_subparagraphs("tls_weak_cipher")
        assert len(result) == len(set(result))

    def test_case_insensitive_matching(self) -> None:
        result_lower = _category_to_subparagraphs("tls_issue")
        result_upper = _category_to_subparagraphs("TLS_ISSUE")
        assert result_lower == result_upper

    def test_all_findings_include_risk_analysis(self) -> None:
        # 21.2.a is the catch-all — every category must map to it.
        for prefix, _ in CATEGORY_SUBPARAGRAPH_MAP:
            cat = prefix + "_something" if prefix else "anything"
            result = _category_to_subparagraphs(cat)
            assert "21.2.a" in result, f"21.2.a missing for category prefix '{prefix}'"


class TestStatusEscalationRules:
    """Pin the sync-risk escalation rules as pure logic (no DB needed)."""

    def _escalate(self, current_status: str, high_risk_count: int) -> str:
        """Mirror the escalation rule from sync_risk."""
        if current_status == "not_started" and high_risk_count > 0:
            return "in_progress"
        return current_status

    def test_not_started_with_critical_escalates(self) -> None:
        assert self._escalate("not_started", high_risk_count=1) == "in_progress"

    def test_not_started_with_high_escalates(self) -> None:
        assert self._escalate("not_started", high_risk_count=3) == "in_progress"

    def test_not_started_with_zero_high_risk_unchanged(self) -> None:
        assert self._escalate("not_started", high_risk_count=0) == "not_started"

    def test_done_never_demoted(self) -> None:
        assert self._escalate("done", high_risk_count=5) == "done"

    def test_in_progress_unchanged_regardless(self) -> None:
        assert self._escalate("in_progress", high_risk_count=10) == "in_progress"

    def test_not_applicable_unchanged(self) -> None:
        assert self._escalate("not_applicable", high_risk_count=2) == "not_applicable"


class TestConstants:
    def test_high_risk_severities_contains_critical_and_high(self) -> None:
        assert "CRITICAL" in _HIGH_RISK_SEVERITIES
        assert "HIGH" in _HIGH_RISK_SEVERITIES
        assert "MEDIUM" not in _HIGH_RISK_SEVERITIES

    def test_resolved_statuses_contains_resolved_and_accepted_risk(self) -> None:
        assert "resolved" in _RESOLVED_STATUSES
        assert "accepted_risk" in _RESOLVED_STATUSES
        assert "open" not in _RESOLVED_STATUSES

    def test_catch_all_is_last_in_map(self) -> None:
        # The empty-prefix catch-all must be last so specific prefixes
        # match first and startswith("") doesn't short-circuit them.
        last_prefix, last_sp = CATEGORY_SUBPARAGRAPH_MAP[-1]
        assert last_prefix == "", "catch-all '' must be the last entry in CATEGORY_SUBPARAGRAPH_MAP"
        assert last_sp == "21.2.a"
