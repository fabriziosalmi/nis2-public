#!/usr/bin/env python3
# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""One version, propagated deterministically, guarded against drift.

The repository declares its version in four hand-edited manifests and derives it
in four more places that nothing kept in step. Every one of those had actually
drifted:

  * `pyproject.toml` x2 and `package.json` x2 said 2.6.10;
  * v2.6.9 shipped with no git tag and no GitHub release at all, leaving a hole
    in the tag sequence between v2.6.8 and v2.6.10;
  * CHANGELOG.md was missing entries for eight tagged releases, one of which
    carried a security fix an operator had no way to learn about;
  * SECURITY.md's supported-versions table still named 2.5.x as current
    throughout the entire 2.6 series — eleven releases — while telling operators
    on 2.4.x that they were still receiving patches.

A single source alone would not have prevented this; nothing was *reading* a
source. What prevents it is a source plus a propagation command plus a check
that fails the build.

Why not a dynamic version resolved from one file at build time: the API
Dockerfile copies only `packages/api`, so a repo-root VERSION would not exist
inside the image and setuptools would fail the build. Literal values in the
manifests, written by `set` and verified by `check`, keep the Docker build
working while removing the hand-editing that caused the drift.

Usage:
    python scripts/version.py check              # CI gate; exit 1 on drift
    python scripts/version.py check --release    # also require a matching git tag
    python scripts/version.py set 2.7.0          # write VERSION and propagate
    python scripts/version.py current            # print the source of truth
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION_FILE = ROOT / "VERSION"

SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


@dataclass
class Mismatch:
    where: str
    expected: str
    found: str
    hint: str = ""


# --------------------------------------------------------------------------
# Readers / writers, one per target
# --------------------------------------------------------------------------


def read_source() -> str:
    if not VERSION_FILE.is_file():
        sys.exit(f"ERROR: {VERSION_FILE.relative_to(ROOT)} is missing — it is the source of truth")
    value = VERSION_FILE.read_text(encoding="utf-8").strip()
    if not SEMVER.match(value):
        sys.exit(f"ERROR: VERSION contains {value!r}, which is not X.Y.Z")
    return value


def _pyproject_version(path: Path) -> str | None:
    # Deliberately not tomllib: this must also WRITE the file, and a
    # parse/serialise round-trip would reformat comments the file relies on.
    # The [project] version line is unambiguous enough to match directly.
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r'^version\s*=\s*"([^"]+)"', line)
        if m:
            return m.group(1)
    return None


def _set_pyproject_version(path: Path, version: str) -> bool:
    text = path.read_text(encoding="utf-8")
    new, n = re.subn(
        r'^version\s*=\s*"[^"]+"', f'version = "{version}"', text, count=1, flags=re.M
    )
    if n and new != text:
        path.write_text(new, encoding="utf-8")
        return True
    return False


def _package_json_version(path: Path) -> str | None:
    return json.loads(path.read_text(encoding="utf-8")).get("version")


def _set_package_json_version(path: Path, version: str) -> bool:
    # Line-level edit rather than json.dump, to preserve key order and the
    # file's existing formatting — a reserialised package.json produces a large,
    # meaningless diff.
    text = path.read_text(encoding="utf-8")
    new, n = re.subn(
        r'^(\s*)"version":\s*"[^"]+"', rf'\g<1>"version": "{version}"', text, count=1, flags=re.M
    )
    if n and new != text:
        path.write_text(new, encoding="utf-8")
        return True
    return False


MANIFESTS = [
    ("packages/api/pyproject.toml", _pyproject_version, _set_pyproject_version),
    ("packages/scanner/pyproject.toml", _pyproject_version, _set_pyproject_version),
    ("package.json", _package_json_version, _set_package_json_version),
    ("packages/web/package.json", _package_json_version, _set_package_json_version),
]


# --------------------------------------------------------------------------
# SECURITY.md supported-versions table
# --------------------------------------------------------------------------

SUPPORT_TABLE = re.compile(
    r"(\| Version \| Status \| Security patches \|\n\|[-| ]+\|\n)(?:\|.*\n)+", re.M
)


def _support_rows(version: str) -> str:
    """Render the table from the version, per the policy stated above it:
    current minor and previous minor supported, older minors end-of-life."""
    major, minor, _ = (int(p) for p in version.split("."))
    current = f"{major}.{minor}.x"
    if minor > 0:
        previous = f"{major}.{minor - 1}.x"
        eol = f"{major}.{minor - 2}" if minor >= 2 else f"{major - 1}.x"
    else:
        previous = f"{major - 1}.x"
        eol = f"{major - 2}.x"
    return (
        f"| {current:<7} | Current | Yes |\n"
        f"| {previous:<7} | Previous | Yes |\n"
        f"| ≤ {eol:<5} | End-of-life | No — please upgrade |\n"
    )


def _security_table(path: Path) -> str | None:
    m = SUPPORT_TABLE.search(path.read_text(encoding="utf-8"))
    return m.group(0) if m else None


def _set_security_table(path: Path, version: str) -> bool:
    text = path.read_text(encoding="utf-8")
    m = SUPPORT_TABLE.search(text)
    if not m:
        return False
    new_block = m.group(1) + _support_rows(version)
    if new_block == m.group(0):
        return False
    path.write_text(text[: m.start()] + new_block + text[m.end():], encoding="utf-8")
    return True


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------


def collect_mismatches(version: str, *, release: bool = False) -> list[Mismatch]:
    problems: list[Mismatch] = []

    for rel, reader, _ in MANIFESTS:
        path = ROOT / rel
        found = reader(path) if path.is_file() else None
        if found != version:
            problems.append(
                Mismatch(rel, version, found or "(absent)", "run: make version-set VERSION=" + version)
            )

    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    if f"## [{version}]" not in changelog:
        problems.append(
            Mismatch(
                "CHANGELOG.md",
                f"an entry for {version}",
                "no entry",
                "eight tagged releases were missing entries when this check was written",
            )
        )

    expected_rows = _support_rows(version)
    table = _security_table(ROOT / "SECURITY.md")
    if table is None:
        problems.append(Mismatch("SECURITY.md", "a supported-versions table", "not found"))
    elif not table.endswith(expected_rows):
        # Report the first row that actually differs. Printing a fixed row
        # produced "expected X, found X" whenever the drift was further down —
        # a check whose diagnostic looks like a false positive teaches people to
        # ignore it.
        want = expected_rows.rstrip("\n").splitlines()
        have = [ln for ln in table.rstrip("\n").splitlines()[2:] if ln.startswith("|")]
        for i, expected_row in enumerate(want):
            actual_row = have[i] if i < len(have) else "(row missing)"
            if actual_row.strip() != expected_row.strip():
                problems.append(
                    Mismatch(
                        "SECURITY.md (supported versions)",
                        expected_row.strip(),
                        actual_row.strip(),
                        "a support policy naming the wrong version is what people "
                        "read when deciding whether to upgrade",
                    )
                )
                break

    if release:
        problems.extend(_release_mismatches(version))
    return problems


def _release_mismatches(version: str) -> list[Mismatch]:
    """Tag checks, only meaningful at release time.

    Left out of the default `check` on purpose: between releases the working
    tree is legitimately ahead of the newest tag, and failing every commit for
    that would train people to ignore the gate.
    """
    problems: list[Mismatch] = []
    try:
        tags = subprocess.run(
            ["git", "tag", "--list"], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout.split()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return [Mismatch("git", "a readable tag list", "git unavailable")]

    if f"v{version}" not in tags:
        problems.append(
            Mismatch(
                "git tag",
                f"v{version}",
                "missing",
                "v2.6.9 shipped with no tag and no GitHub release, leaving a hole "
                "in the sequence between v2.6.8 and v2.6.10",
            )
        )
    return problems


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def cmd_check(args: argparse.Namespace) -> int:
    version = read_source()
    problems = collect_mismatches(version, release=args.release)
    if not problems:
        scope = "manifests, CHANGELOG, SECURITY.md" + (", git tag" if args.release else "")
        print(f"  version {version}: consistent across {scope}")
        return 0

    print(f"\n  VERSION says {version}, but:\n")
    width = max(len(p.where) for p in problems)
    for p in problems:
        print(f"    {p.where:<{width}}  expected {p.expected}   found {p.found}")
        if p.hint:
            print(f"    {'':<{width}}  -> {p.hint}")
    # Tag drift is not fixable by re-propagating the version, so do not suggest
    # a command that would leave the tree unchanged and the check still red.
    if any(p.where == "git tag" for p in problems):
        print(f"\n  Tag the release:  git tag v{version} && git push origin v{version}")
    if any(p.where != "git tag" for p in problems):
        print(f"\n  Fix the rest with:  make version-set VERSION={version}")
    print()
    return 1


def cmd_set(args: argparse.Namespace) -> int:
    version = args.version
    if not SEMVER.match(version):
        sys.exit(f"ERROR: {version!r} is not X.Y.Z")

    changed: list[str] = []
    if not VERSION_FILE.is_file() or VERSION_FILE.read_text(encoding="utf-8").strip() != version:
        VERSION_FILE.write_text(version + "\n", encoding="utf-8")
        changed.append("VERSION")

    for rel, _, writer in MANIFESTS:
        if writer(ROOT / rel, version):
            changed.append(rel)
    if _set_security_table(ROOT / "SECURITY.md", version):
        changed.append("SECURITY.md")

    print(f"  version set to {version}")
    for c in changed:
        print(f"    updated {c}")
    if not changed:
        print("    (everything already agreed — nothing to write)")

    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    if f"## [{version}]" not in changelog:
        print(
            f"\n  CHANGELOG.md has no `## [{version}]` entry yet — add one before\n"
            f"  releasing. `make version-check` will fail until you do."
        )
    return 0


def cmd_current(_: argparse.Namespace) -> int:
    print(read_source())
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command")

    p_check = sub.add_parser("check", help="fail if any target disagrees with VERSION")
    p_check.add_argument(
        "--release",
        action="store_true",
        help="also require the matching git tag to exist",
    )
    p_check.set_defaults(func=cmd_check)

    p_set = sub.add_parser("set", help="write VERSION and propagate it")
    p_set.add_argument("version")
    p_set.set_defaults(func=cmd_set)

    sub.add_parser("current", help="print the source of truth").set_defaults(func=cmd_current)

    args = parser.parse_args()
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
