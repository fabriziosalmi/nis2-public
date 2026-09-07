# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""VERSION is the source of truth, and everything derived from it agrees.

The repository declared its version in four hand-edited manifests and derived it
in four more places nothing kept in step. Every one had drifted at once:

  * v2.6.9 shipped with no git tag and no GitHub release, leaving a hole in the
    tag sequence between v2.6.8 and v2.6.10;
  * CHANGELOG.md was missing entries for eight tagged releases, one of which
    carried a security fix (Prometheus removed from its host port, where it
    served unauthenticated internal metrics) that an operator deciding whether
    to upgrade had no way to learn about;
  * SECURITY.md named 2.5.x as the current supported minor throughout the entire
    2.6 series — eleven releases — while telling operators on 2.4.x that they
    were still receiving patches.

A single source alone would not have stopped any of that, because nothing was
reading a source. What stops it is the source plus a propagation command plus
this check, which fails the build.

The suite runs in CI as `version-consistency`; these tests additionally pin the
tool's own behaviour so the gate cannot be weakened without noticing.
"""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "scripts" / "version.py"


def _load_module():
    """Import scripts/version.py by path.

    It must be registered in sys.modules BEFORE exec_module: the module defines
    a @dataclass, and dataclasses resolves annotations through
    sys.modules[cls.__module__], which is None for a module still being executed.
    """
    spec = importlib.util.spec_from_file_location("nis2_version_tool", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


version_tool = _load_module()


def test_version_file_exists_and_is_semver():
    value = (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    assert re.fullmatch(r"\d+\.\d+\.\d+", value), f"VERSION holds {value!r}"


def test_repository_is_currently_consistent():
    """The gate, run against the real tree — this is what CI enforces."""
    problems = version_tool.collect_mismatches(version_tool.read_source())
    assert not problems, "\n".join(
        f"{p.where}: expected {p.expected}, found {p.found}" for p in problems
    )


@pytest.mark.parametrize(
    "manifest",
    [
        "packages/api/pyproject.toml",
        "packages/scanner/pyproject.toml",
        "package.json",
        "packages/web/package.json",
    ],
)
def test_every_manifest_matches_the_source(manifest: str):
    """Named individually so a failure says which file drifted."""
    expected = version_tool.read_source()
    path = REPO_ROOT / manifest
    if manifest.endswith(".json"):
        found = json.loads(path.read_text(encoding="utf-8"))["version"]
    else:
        found = version_tool._pyproject_version(path)
    assert found == expected, f"{manifest} says {found}, VERSION says {expected}"


def test_changelog_documents_the_current_version():
    version = version_tool.read_source()
    changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## [{version}]" in changelog


def test_security_policy_names_the_current_minor():
    """A support policy naming the wrong version is itself a defect: it is what
    people consult when deciding whether they need to upgrade."""
    major, minor, _ = version_tool.read_source().split(".")
    table = version_tool._security_table(REPO_ROOT / "SECURITY.md")
    assert table is not None
    assert f"| {major}.{minor}.x" in table


@pytest.fixture
def tmp_repo(tmp_path: Path) -> Path:
    """A minimal copy of the files the tool touches."""
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "version.py").write_text(
        SCRIPT.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "VERSION").write_text("1.2.3\n", encoding="utf-8")
    for rel in ("packages/api", "packages/scanner", "packages/web"):
        (tmp_path / rel).mkdir(parents=True)
    for rel in ("packages/api/pyproject.toml", "packages/scanner/pyproject.toml"):
        (tmp_path / rel).write_text('[project]\nversion = "1.2.3"\n', encoding="utf-8")
    for rel in ("package.json", "packages/web/package.json"):
        (tmp_path / rel).write_text('{\n  "version": "1.2.3"\n}\n', encoding="utf-8")
    (tmp_path / "CHANGELOG.md").write_text("## [1.2.3] - 2026-01-01\n", encoding="utf-8")
    (tmp_path / "SECURITY.md").write_text(_table("1.2", "1.1", "1.0"), encoding="utf-8")
    return tmp_path


def _table(current: str, previous: str, eol: str, previous_note: str = "Yes") -> str:
    return (
        "| Version | Status | Security patches |\n"
        "|---------|--------|------------------|\n"
        f"| {current}.x   | Current | Yes |\n"
        f"| {previous}.x   | Previous | {previous_note} |\n"
        f"| \u2264 {eol}   | End-of-life | No \u2014 please upgrade |\n"
    )


def _run_check(repo: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(repo / "scripts" / "version.py"), "check"],
        capture_output=True,
        text=True,
    )


class TestTheGateActuallyFails:
    """A check that never goes red is decoration. These drive it negative."""

    def test_a_consistent_tree_passes(self, tmp_repo: Path):
        """Control: without this, a gate that always failed would look correct."""
        result = _run_check(tmp_repo)
        assert result.returncode == 0, result.stdout

    def test_manifest_drift_fails(self, tmp_repo: Path):
        (tmp_repo / "packages/web/package.json").write_text(
            '{\n  "version": "9.9.9"\n}\n', encoding="utf-8"
        )
        result = _run_check(tmp_repo)
        assert result.returncode == 1
        assert "packages/web/package.json" in result.stdout

    def test_missing_changelog_entry_fails(self, tmp_repo: Path):
        (tmp_repo / "CHANGELOG.md").write_text("## [1.2.2] - 2026-01-01\n", encoding="utf-8")
        result = _run_check(tmp_repo)
        assert result.returncode == 1
        assert "CHANGELOG.md" in result.stdout

    def test_stale_security_table_fails(self, tmp_repo: Path):
        """The exact drift that went unnoticed for eleven releases."""
        (tmp_repo / "SECURITY.md").write_text(_table("1.1", "1.0", "0.9"), encoding="utf-8")
        result = _run_check(tmp_repo)
        assert result.returncode == 1
        assert "SECURITY.md" in result.stdout

    def test_the_diagnostic_names_the_row_that_differs(self, tmp_repo: Path):
        """An earlier revision printed a fixed row, so a drift further down read
        as "expected X, found X" — a diagnostic that looks like a false positive
        teaches people to ignore the gate."""
        (tmp_repo / "SECURITY.md").write_text(
            _table("1.2", "1.1", "1.0", previous_note="Yes (until 2099-01-01)"),
            encoding="utf-8",
        )
        result = _run_check(tmp_repo)
        assert result.returncode == 1
        assert "2099-01-01" in result.stdout, (
            "the diagnostic must quote the row that actually differs"
        )


class TestSetPropagates:
    def test_set_writes_every_manifest_and_the_support_table(self, tmp_repo: Path):
        subprocess.run(
            [sys.executable, str(tmp_repo / "scripts" / "version.py"), "set", "2.0.0"],
            capture_output=True,
            text=True,
            check=True,
        )
        assert (tmp_repo / "VERSION").read_text(encoding="utf-8").strip() == "2.0.0"
        assert '"version": "2.0.0"' in (tmp_repo / "package.json").read_text(encoding="utf-8")
        assert '"version": "2.0.0"' in (
            tmp_repo / "packages/web/package.json"
        ).read_text(encoding="utf-8")
        for rel in ("packages/api/pyproject.toml", "packages/scanner/pyproject.toml"):
            assert 'version = "2.0.0"' in (tmp_repo / rel).read_text(encoding="utf-8")
        assert "| 2.0.x" in (tmp_repo / "SECURITY.md").read_text(encoding="utf-8")

    def test_set_then_check_disagree_only_on_the_changelog(self, tmp_repo: Path):
        """A bump legitimately leaves the CHANGELOG behind until it is written —
        the gate must say so rather than passing silently."""
        subprocess.run(
            [sys.executable, str(tmp_repo / "scripts" / "version.py"), "set", "2.0.0"],
            capture_output=True, text=True, check=True,
        )
        result = _run_check(tmp_repo)
        assert result.returncode == 1
        assert "CHANGELOG.md" in result.stdout
        assert "pyproject" not in result.stdout
