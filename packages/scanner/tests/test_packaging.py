# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""Data files the scanner needs at runtime must ship with it.

`secret_patterns.yaml` is code, not documentation: secrets.py loads it at import
and silently falls back to a reduced hardcoded set when it is missing.
`pyproject.toml` declared the packages but not the package data, so setuptools
shipped only the .py files — and every containerised deployment ran secret
detection on the fallback while the README advertised the full pattern set.

Found by running the scanner inside the built image and reading the warning it
emitted. It is the only one of this platform's silent degradations that said
anything at all, and it still went unnoticed, because nobody reads container
logs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

PACKAGE_DIR = Path(__file__).resolve().parents[1] / "nis2scan"
PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def _data_files() -> list[Path]:
    """Non-Python files the package needs at runtime."""
    return sorted(p for p in PACKAGE_DIR.glob("*.yaml"))


def test_the_package_has_data_files_worth_shipping():
    """Sanity: the assertions below are vacuous if the glob finds nothing."""
    assert _data_files(), f"no .yaml found under {PACKAGE_DIR}"


def test_pyproject_declares_package_data():
    """Without this section setuptools silently omits them from the wheel."""
    text = PYPROJECT.read_text(encoding="utf-8")
    assert "[tool.setuptools.package-data]" in text, (
        "pyproject.toml declares no package-data, so runtime data files are "
        "dropped from the built distribution"
    )
    assert '"*.yaml"' in text


@pytest.mark.parametrize("name", [p.name for p in _data_files()])
def test_each_data_file_is_importable_from_the_installed_package(name: str):
    """Resolve through the imported module, the way the code does at runtime.

    Checking the source tree would pass even from a wheel that omitted the file;
    this fails when the installed package lacks it.
    """
    import nis2scan

    installed = Path(nis2scan.__file__).parent / name
    assert installed.is_file(), (
        f"{name} is missing from the installed package at {installed}. "
        f"secrets.py degrades to a reduced hardcoded pattern set when this "
        f"happens, and only says so in a log line."
    )


def test_the_full_pattern_set_loads_rather_than_the_fallback():
    """The behaviour the packaging exists to protect."""
    from nis2scan.secrets import SecretsDetector

    detector = SecretsDetector()
    patterns = getattr(detector, "patterns", None) or getattr(detector, "PATTERNS", None)
    assert patterns, "SecretsDetector exposes no pattern collection to assert on"
    assert len(patterns) >= 10, (
        f"only {len(patterns)} patterns loaded — this is the reduced fallback, "
        f"not secret_patterns.yaml"
    )
