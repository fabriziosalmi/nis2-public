# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
"""I1: every NIS2 Art. 21(2) reference in compliance.py must use the canonical
letter for its topic. Pre-fix, cryptography was tagged 21.2.g (should be h) and
cyber hygiene 21.2.f (should be g), and those wrong letters were persisted onto
auditable Finding records."""
import re
from pathlib import Path

from nis2scan.compliance import SUBPARAGRAPHS

_SRC = Path(__file__).resolve().parents[1] / "nis2scan" / "compliance.py"

# Canonical topic-keyword -> Art. 21(2) letter.
LABEL_LETTER = {
    "cryptography": "h",
    "cyber hygiene": "g",
    "network security": "e",
    "net security": "e",
    "supply chain": "d",
    "access control": "i",
    "business continuity": "c",
    "secured communications": "j",
    "vulnerability handling": "e",
    "security in acquisition": "e",
}


def test_subparagraphs_are_canonical():
    assert set(SUBPARAGRAPHS) == set("abcdefghij")
    # the two letters the bug swapped
    assert "ryptograph" in SUBPARAGRAPHS["h"]
    assert "hygiene" in SUBPARAGRAPHS["g"].lower()
    assert "effectiveness" in SUBPARAGRAPHS["f"].lower()


def test_every_finding_reference_uses_the_canonical_letter():
    src = _SRC.read_text(encoding="utf-8")
    refs = re.findall(r"21\.2\.([a-j]) \(([^)]+)\)", src)
    assert refs, "no NIS2 references matched — regex/source drift"

    checked = 0
    for letter, label in refs:
        key = next((k for k in LABEL_LETTER if k in label.lower()), None)
        if key is None:
            continue  # label without a known topic keyword — not asserted
        assert letter == LABEL_LETTER[key], (
            f"NIS2 letter mismatch: '21.2.{letter} ({label})' — "
            f"a '{key}' measure must be 21.2.{LABEL_LETTER[key]}"
        )
        checked += 1
    # sanity: we actually validated the bulk of the references
    assert checked >= 15, f"only validated {checked} references"


def test_no_cryptography_tagged_g_or_cyber_hygiene_tagged_f():
    """Regression lock on the exact swap the review found."""
    src = _SRC.read_text(encoding="utf-8")
    assert "21.2.g (Cryptography" not in src
    assert "21.2.f (Cyber Hygiene" not in src


class TestTheMatrixCanAnswerOnWhatEvidence:
    """The Art. 21 matrix is what lands on an auditor's desk.

    The README's honest disclaimer does not travel with the PDF, so the table has
    to defend itself. It previously claimed:

      * "d) Supply Chain Security: Partially Automated", on the strength of
        checking the `integrity` attribute of external <script> tags — Art.
        21(2)(d) concerns supplier assessment, contracts and monitoring, and SRI
        is not a partial automation of that but a different subject;
      * "g) Cyber Hygiene & Training: Partially Automated", on response headers.
        Training is people and has no observable HTTP surface;
      * bare "Automated" for (e) and (h), claiming a completeness that a
        public-surface probe cannot have.

    These tests fail if any sub-paragraph reasserts more than the scanner can
    evidence.
    """

    def _matrix(self):
        from nis2scan.compliance import ComplianceEngine
        from nis2scan.config import Config, Targets

        engine = ComplianceEngine(Config(targets=Targets(ip_ranges=["127.0.0.1"]), features={}))
        return engine.evaluate([], scan_id="test").compliance_matrix

    def test_supply_chain_is_not_claimed_from_a_web_scan(self):
        value = self._matrix()["d) Supply Chain Security"]
        assert "Not Assessed" in value, (
            f"(d) claims {value!r}; supplier assessment, contracts and monitoring "
            f"are organisational controls with no external surface"
        )

    def test_training_is_not_claimed_from_response_headers(self):
        value = self._matrix()["g) Cyber Hygiene & Training"]
        assert "Not Assessed" in value, f"(g) claims {value!r}; training is not observable over HTTP"

    def test_no_subparagraph_claims_bare_automation(self):
        """"Automated" with no qualifier reads as "this control is covered".

        A scan sees the public surface; every genuine automation here is partial
        and must say what it covers.
        """
        for key, value in self._matrix().items():
            assert value.strip() != "Automated", (
                f"{key} claims unqualified 'Automated'; name the evidence and its limits"
            )

    def test_every_partial_claim_names_its_evidence(self):
        """A parenthetical is the whole point: it is the answer to "on what
        evidence?" that the table must carry on its own."""
        for key, value in self._matrix().items():
            if value.startswith("Partially Automated"):
                assert "(" in value and ")" in value, (
                    f"{key} claims partial automation without naming what it rests on"
                )
