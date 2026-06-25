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
