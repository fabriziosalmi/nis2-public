# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""Every CVSS number the platform publishes is computed from its vector.

The scores were hand-picked. Of the 28 findings that declared one, exactly 7
agreed with the vector printed beside them in the archival PDF/A dossier: an
expired certificate was labelled 7.5 where its own vector computes 8.2, an open
zone transfer 9.0 where it computes 8.6. Twelve carried a number with no vector
at all, and one 9.8 was annotated in the source as "assuming critical CVEs
exist" — a banner match presented to an auditor as a critical vulnerability.

That is the liability surface. The dossier is sold as evidence for a NIS2
Art. 21 posture; "on what basis is this a 7.5?" has no good answer when the
vector is absent, and a worse one when the vector is right there and disagrees.

So: the score is a pure function of the vector, and a finding with no defensible
vector publishes no score at all. These tests hold both halves.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from nis2scan import cvss
from nis2scan.compliance import ComplianceFinding

_SOURCE = Path(__file__).resolve().parents[1] / "nis2scan" / "compliance.py"


class TestAgainstThePublishedSpecification:
    """Reference vectors with scores published by FIRST.org and NVD.

    An arithmetic bug here would be invisible — every number would still look
    plausible — which is exactly why the check is against externally published
    values rather than against our own output.
    """

    @pytest.mark.parametrize(
        "vector,expected",
        [
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # CVE-2021-44228 shape
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),   # information disclosure
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),   # remote DoS
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),  # ceiling
            ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),   # local privesc
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),   # reflected XSS
            ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),   # near the floor
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),   # no impact
        ],
    )
    def test_reference_vectors(self, vector: str, expected: float):
        assert cvss.base_score(vector) == expected

    def test_roundup_is_the_specifications_roundup_not_pythons(self):
        """The spec defines Roundup in integer arithmetic precisely so binary
        floating point cannot shift a score. Python's round() would turn 8.05
        into 8.0 where CVSS requires 8.1."""
        assert cvss._roundup(8.05) == 8.1
        assert cvss._roundup(4.0) == 4.0

    def test_scope_change_is_not_ignored(self):
        """S:C changes both the privilege weights and the final multiplier. A
        calculator that drops it under-reports every cross-boundary finding."""
        unchanged = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        changed = unchanged.replace("S:U", "S:C")
        assert cvss.base_score(changed) > cvss.base_score(unchanged)


class TestNoScoreWithoutAVector:
    def test_a_missing_vector_yields_no_score(self):
        """Not 0.0, and not a default. None — so the report prints an empty
        cell an auditor can ask about instead of a number nobody can defend."""
        assert cvss.score_for(None) is None
        assert cvss.score_for("") is None

    @pytest.mark.parametrize(
        "vector",
        [
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",              # no CVSS: prefix
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N",         # A missing
            "CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",     # AV:Z does not exist
            "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",              # v2, not v3
        ],
    )
    def test_a_malformed_vector_yields_no_score(self, vector: str):
        """Fail closed. Silently substituting a default is how the hand-picked
        numbers got there in the first place."""
        assert cvss.score_for(vector) is None
        with pytest.raises(cvss.InvalidVector):
            cvss.base_score(vector)


class TestTheFindingDerivesItsOwnScore:
    def test_a_passed_in_score_is_ignored(self):
        """The whole point. If a caller can hand-set the number, the two values
        drift apart again the first time someone edits one and not the other."""
        f = ComplianceFinding(
            severity="HIGH",
            category="ENCRYPTION",
            message="test",
            rationale="test",
            target="203.0.113.1",
            cvss_base_score=9.9,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        )
        assert f.cvss_base_score == 7.5

    def test_a_finding_without_a_vector_publishes_nothing(self):
        f = ComplianceFinding(
            severity="LOW",
            category="LEGAL",
            message="Italian P.IVA Not Found",
            rationale="test",
            target="example.com",
        )
        assert f.cvss_base_score is None


def _finding_blocks() -> list[str]:
    """Every ComplianceFinding(...) constructed in compliance.py, as source."""
    source = _SOURCE.read_text()
    blocks = []
    for match in re.finditer(r"ComplianceFinding\(", source):
        i, depth = match.end(), 1
        while depth:
            depth += (source[i] == "(") - (source[i] == ")")
            i += 1
        blocks.append(source[match.end() : i - 1])
    return blocks


class TestTheShippedFindings:
    """Structural, against the source, because what regresses is a call site.

    Exercising these through a live scan would need the network and would only
    reach the handful of findings that particular target happens to trigger.
    """

    def test_there_are_findings_to_check(self):
        assert len(_finding_blocks()) > 25

    def test_no_finding_hand_sets_a_score(self):
        offenders = [
            re.search(r'message=f?"([^"]*)"', b).group(1)
            for b in _finding_blocks()
            if "cvss_base_score=" in b
        ]
        assert not offenders, (
            f"these findings pass a hand-picked cvss_base_score: {offenders}. "
            f"It is ignored at runtime, but in the source it reads as truth."
        )

    def test_every_declared_vector_computes(self):
        """A vector the calculator rejects means a finding that silently lost
        its score — the failure mode is an empty column, not an exception."""
        for block in _finding_blocks():
            match = re.search(r'cvss_vector="([^"]*)"', block)
            if not match:
                continue
            name = re.search(r'message=f?"([^"]*)"', block).group(1)
            assert cvss.score_for(match.group(1)) is not None, (
                f"{name!r} declares an uncomputable vector: {match.group(1)}"
            )

    @pytest.mark.parametrize(
        "message",
        [
            "Italian P.IVA Not Found",
            "Privacy Policy Link Not Found",
            "Cookie Consent Banner Not Detected",
            "Security.txt Missing",
            "Incomplete Domain Registration Data",
        ],
    )
    def test_non_vulnerabilities_carry_no_cvss(self, message: str):
        """A missing VAT number is a consumer-law matter and a missing cookie
        banner a GDPR one. Neither is a vulnerability, and attaching a CVSS
        score to them is the clearest possible evidence that the numbers were
        decorative."""
        for block in _finding_blocks():
            if message in block:
                assert "cvss_vector=" not in block, (
                    f"{message!r} is not a vulnerability and must publish no CVSS score"
                )
                return
        pytest.fail(f"finding {message!r} no longer exists — update this test")

    def test_eol_software_is_not_scored_on_an_assumption(self):
        """It was 9.8, annotated 'assuming critical CVEs exist for EOL
        software'. CVSS scores a specific vulnerability; a banner match is not
        one, and banners are spoofable and stale where distributions backport
        fixes without changing the version string."""
        for block in _finding_blocks():
            if "Obsolete/EOL Software Detected" in block:
                assert "cvss_vector=" not in block
                assert "cvss_base_score=" not in block
                return
        pytest.fail("the EOL software finding no longer exists — update this test")
