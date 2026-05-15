# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Tests for the vendor risk scoring formula (NIS2 Art. 18).

Exercises compute_vendor_score() as a pure function — no database or
network required. Each test pins one factor at a time so a future
weight change fails loudly at the specific factor that changed.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock


from app.routers.vendors import (
    SCORE_FACTORS,
    SCORE_FORMULA_VERSION,
    compute_vendor_score,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _vendor(**kwargs) -> MagicMock:
    """Return a minimal vendor-like object with sensible defaults."""
    v = MagicMock()
    v.has_security_certification = kwargs.get("has_security_certification", None)
    v.data_access_level = kwargs.get("data_access_level", "none")
    v.last_audit_date = kwargs.get("last_audit_date", None)
    v.geographic_location = kwargs.get("geographic_location", None)
    v.security_clauses = kwargs.get("security_clauses", None)
    return v


def _recent(months: float) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=months * 30.44)


# ---------------------------------------------------------------------------
# Score structure
# ---------------------------------------------------------------------------

class TestScoreStructure:
    def test_returns_computed_score(self) -> None:
        result = compute_vendor_score(_vendor())
        assert "computed_score" in result

    def test_score_is_int_in_range(self) -> None:
        result = compute_vendor_score(_vendor())
        assert 0 <= result["computed_score"] <= 100

    def test_returns_formula_version(self) -> None:
        result = compute_vendor_score(_vendor())
        assert result["formula_version"] == SCORE_FORMULA_VERSION

    def test_breakdown_has_five_factors(self) -> None:
        result = compute_vendor_score(_vendor())
        assert len(result["breakdown"]) == 5

    def test_breakdown_factor_ids_match_formula(self) -> None:
        result = compute_vendor_score(_vendor())
        formula_ids = {f["factor_id"] for f in SCORE_FACTORS}
        breakdown_ids = {f["factor_id"] for f in result["breakdown"]}
        assert formula_ids == breakdown_ids

    def test_earned_never_exceeds_max_weight(self) -> None:
        # Even with a maximally good vendor, no factor exceeds its ceiling.
        v = _vendor(
            has_security_certification="ISO27001",
            data_access_level="none",
            last_audit_date=_recent(1),
            geographic_location="EU",
            security_clauses={
                "sla": True, "audit_rights": True, "incident_notification": True,
                "data_breach_clause": True, "sub_processor_clause": True,
            },
        )
        result = compute_vendor_score(v)
        for item in result["breakdown"]:
            assert item["earned"] <= item["max_weight"], (
                f"Factor {item['factor_id']} earned {item['earned']} "
                f"but max is {item['max_weight']}"
            )

    def test_sum_of_earned_equals_computed_score(self) -> None:
        v = _vendor(
            has_security_certification="SOC2",
            data_access_level="operational",
            last_audit_date=_recent(10),
            geographic_location="EU",
            security_clauses={"sla": True, "audit_rights": True},
        )
        result = compute_vendor_score(v)
        assert sum(f["earned"] for f in result["breakdown"]) == result["computed_score"]

    def test_perfect_vendor_scores_100(self) -> None:
        v = _vendor(
            has_security_certification="ISO27001",
            data_access_level="none",
            last_audit_date=_recent(1),
            geographic_location="EU",
            security_clauses={
                "sla": True, "audit_rights": True, "incident_notification": True,
                "data_breach_clause": True, "sub_processor_clause": True,
            },
        )
        assert compute_vendor_score(v)["computed_score"] == 100

    def test_worst_vendor_scores_zero(self) -> None:
        v = _vendor(
            has_security_certification=None,
            data_access_level="critical",
            last_audit_date=None,
            geographic_location="third_country",
            security_clauses=None,
        )
        assert compute_vendor_score(v)["computed_score"] == 0


# ---------------------------------------------------------------------------
# Factor: Security certification (max 25)
# ---------------------------------------------------------------------------

class TestCertificationFactor:
    def _cert_score(self, cert: str | None) -> int:
        v = _vendor(
            has_security_certification=cert,
            data_access_level="critical",   # zero all others
            geographic_location="third_country",
            security_clauses=None,
        )
        r = compute_vendor_score(v)
        return next(f["earned"] for f in r["breakdown"] if f["factor_id"] == "certification")

    def test_iso27001_scores_25(self) -> None:
        assert self._cert_score("ISO27001") == 25

    def test_iso27001_with_space_scores_25(self) -> None:
        assert self._cert_score("ISO 27001:2022") == 25

    def test_soc2_type2_scores_22(self) -> None:
        assert self._cert_score("SOC2 Type2") == 22

    def test_csa_star_scores_18(self) -> None:
        assert self._cert_score("CSA_STAR") == 18

    def test_soc2_without_type2_scores_15(self) -> None:
        assert self._cert_score("SOC2") == 15

    def test_other_cert_scores_10(self) -> None:
        assert self._cert_score("PCI-DSS") == 10

    def test_none_scores_0(self) -> None:
        assert self._cert_score(None) == 0

    def test_empty_string_scores_0(self) -> None:
        assert self._cert_score("") == 0


# ---------------------------------------------------------------------------
# Factor: Data access level (max 25)
# ---------------------------------------------------------------------------

class TestDataAccessFactor:
    def _da_score(self, level: str) -> int:
        v = _vendor(data_access_level=level, geographic_location="third_country", security_clauses=None)
        r = compute_vendor_score(v)
        return next(f["earned"] for f in r["breakdown"] if f["factor_id"] == "data_access")

    def test_none_scores_25(self) -> None:
        assert self._da_score("none") == 25

    def test_metadata_scores_20(self) -> None:
        assert self._da_score("metadata") == 20

    def test_operational_scores_12(self) -> None:
        assert self._da_score("operational") == 12

    def test_confidential_scores_5(self) -> None:
        assert self._da_score("confidential") == 5

    def test_critical_scores_0(self) -> None:
        assert self._da_score("critical") == 0


# ---------------------------------------------------------------------------
# Factor: Audit recency (max 20)
# ---------------------------------------------------------------------------

class TestAuditRecencyFactor:
    def _audit_score(self, months_ago: float | None) -> int:
        date = _recent(months_ago) if months_ago is not None else None
        v = _vendor(last_audit_date=date, data_access_level="critical", geographic_location="third_country")
        r = compute_vendor_score(v)
        return next(f["earned"] for f in r["breakdown"] if f["factor_id"] == "audit_recency")

    def test_no_audit_scores_0(self) -> None:
        assert self._audit_score(None) == 0

    def test_3_months_ago_scores_20(self) -> None:
        assert self._audit_score(3) == 20

    def test_8_months_ago_scores_15(self) -> None:
        assert self._audit_score(8) == 15

    def test_18_months_ago_scores_8(self) -> None:
        assert self._audit_score(18) == 8

    def test_30_months_ago_scores_3(self) -> None:
        assert self._audit_score(30) == 3

    def test_40_months_ago_scores_0(self) -> None:
        assert self._audit_score(40) == 0


# ---------------------------------------------------------------------------
# Factor: Geographic location (max 15)
# ---------------------------------------------------------------------------

class TestGeographyFactor:
    def _geo_score(self, location: str | None) -> int:
        v = _vendor(geographic_location=location, data_access_level="critical", security_clauses=None)
        r = compute_vendor_score(v)
        return next(f["earned"] for f in r["breakdown"] if f["factor_id"] == "geography")

    def test_eu_scores_15(self) -> None:
        assert self._geo_score("EU") == 15

    def test_eea_scores_14(self) -> None:
        assert self._geo_score("EEA") == 14

    def test_adequacy_decision_scores_10(self) -> None:
        assert self._geo_score("adequacy_decision") == 10

    def test_third_country_scores_0(self) -> None:
        assert self._geo_score("third_country") == 0

    def test_unknown_scores_5(self) -> None:
        assert self._geo_score("somewhere") == 5

    def test_none_scores_5(self) -> None:
        assert self._geo_score(None) == 5


# ---------------------------------------------------------------------------
# Factor: Security clauses (max 15, 3 pts each)
# ---------------------------------------------------------------------------

class TestClausesFactor:
    def _clause_score(self, clauses: dict | None) -> int:
        v = _vendor(security_clauses=clauses, data_access_level="critical", geographic_location="third_country")
        r = compute_vendor_score(v)
        return next(f["earned"] for f in r["breakdown"] if f["factor_id"] == "clauses")

    def test_no_clauses_scores_0(self) -> None:
        assert self._clause_score(None) == 0

    def test_empty_dict_scores_0(self) -> None:
        assert self._clause_score({}) == 0

    def test_one_clause_scores_3(self) -> None:
        assert self._clause_score({"sla": True}) == 3

    def test_three_clauses_scores_9(self) -> None:
        assert self._clause_score({"sla": True, "audit_rights": True, "incident_notification": True}) == 9

    def test_all_five_clauses_scores_15(self) -> None:
        clauses = {
            "sla": True, "audit_rights": True, "incident_notification": True,
            "data_breach_clause": True, "sub_processor_clause": True,
        }
        assert self._clause_score(clauses) == 15

    def test_false_values_not_counted(self) -> None:
        # Only truthy values count.
        assert self._clause_score({"sla": False, "audit_rights": True}) == 3

    def test_extra_unknown_keys_do_not_inflate_score(self) -> None:
        clauses = {
            "sla": True, "audit_rights": True, "incident_notification": True,
            "data_breach_clause": True, "sub_processor_clause": True,
            "extra_magic_clause": True,  # unknown — should not push beyond 15
        }
        assert self._clause_score(clauses) == 15


# ---------------------------------------------------------------------------
# Formula metadata
# ---------------------------------------------------------------------------

class TestFormulaMetadata:
    def test_formula_version_is_string(self) -> None:
        assert isinstance(SCORE_FORMULA_VERSION, str)
        assert len(SCORE_FORMULA_VERSION) > 0

    def test_score_factors_has_five_entries(self) -> None:
        assert len(SCORE_FACTORS) == 5

    def test_factor_weights_sum_to_100(self) -> None:
        total = sum(f["max_weight"] for f in SCORE_FACTORS)
        assert total == 100, f"Factor weights sum to {total}, expected 100"

    def test_each_factor_has_required_keys(self) -> None:
        required = {"factor_id", "label", "max_weight", "description", "source_field"}
        for f in SCORE_FACTORS:
            assert required.issubset(set(f.keys())), f"Factor {f.get('factor_id')} missing keys"
