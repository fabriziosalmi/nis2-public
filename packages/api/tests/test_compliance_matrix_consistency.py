# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""The Art. 21 status of each sub-paragraph is claimed in three places.

The README carries a summary matrix, and docs/reference/compliance-matrix.md
carries the detailed one, in English and Italian. All three tell a prospective
user — and an auditor reading over their shoulder — whether (h) cryptography is
*Implemented* or *Partial*. Three hand-maintained copies of the same claim is
how the wiki ended up documenting a deployment that would not start.

They agree today. This keeps them agreeing, and fails naming the sub-paragraph
that diverged rather than leaving it to be noticed by a reader.
"""

from __future__ import annotations

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[3]
README = ROOT / "README.md"
MATRIX_EN = ROOT / "docs" / "reference" / "compliance-matrix.md"
MATRIX_IT = ROOT / "docs" / "it" / "reference" / "compliance-matrix.md"

# A row: | (a) Title | Scope | **Partial** — why | How the platform supports it |
_ROW = re.compile(r"^\|\s*\((?P<letter>[a-j])\)[^|]*\|[^|]*\|\s*(?P<status>[^|]+?)\s*\|")

# The Italian matrix translates the status word. Comparing the words verbatim
# would fail on the translation rather than on a disagreement, so both sides are
# reduced to the same three states first.
_CANON = {
    "implemented": "implemented",
    "implementato": "implemented",
    "partial": "partial",
    "parziale": "partial",
    "manual": "manual",
    "manuale": "manual",
}


def _statuses(path: pathlib.Path) -> dict[str, str]:
    statuses: dict[str, str] = {}
    for line in path.read_text().splitlines():
        m = _ROW.match(line)
        if not m:
            continue
        # Strip emphasis and any trailing qualifier: "**Implemented** — end to
        # end" and "Implemented (manual verification)" are the same claim.
        word = re.split(r"[—(]", m.group("status").replace("*", ""))[0].strip().lower()
        canonical = _CANON.get(word)
        assert canonical, f"{path.name}: unrecognised status {word!r} for ({m.group('letter')})"
        statuses[m.group("letter")] = canonical
    return statuses


def test_every_subparagraph_is_covered():
    """Ten sub-paragraphs, (a) through (j), in each document."""
    for path in (README, MATRIX_EN, MATRIX_IT):
        found = set(_statuses(path))
        assert found == set("abcdefghij"), (
            f"{path.name} covers {sorted(found)}, not (a) through (j)"
        )


@pytest.mark.parametrize("other", [MATRIX_EN, MATRIX_IT], ids=["en", "it"])
def test_the_matrix_agrees_with_the_readme(other: pathlib.Path):
    readme = _statuses(README)
    matrix = _statuses(other)
    disagreements = {
        letter: (readme[letter], matrix[letter])
        for letter in sorted(readme)
        if readme[letter] != matrix[letter]
    }
    assert not disagreements, (
        "README and "
        + str(other.relative_to(ROOT))
        + " disagree on: "
        + ", ".join(
            f"({letter}) README says {a}, the matrix says {b}"
            for letter, (a, b) in disagreements.items()
        )
    )


def test_the_two_translations_agree():
    """A reader who switches language must not get a different answer."""
    en, it = _statuses(MATRIX_EN), _statuses(MATRIX_IT)
    assert en == it, (
        "the English and Italian matrices disagree on: "
        + ", ".join(f"({k}) {en[k]} vs {it[k]}" for k in sorted(en) if en[k] != it.get(k))
    )
