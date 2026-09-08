#!/usr/bin/env python3
# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""Count the HTTP surface from the code, and check the README against it.

The README's API-surface table is maintained by hand and had drifted: seven of
twenty routers carried stale counts and the surface was understated by fourteen
endpoints — including the asset ownership-verification flow and the Art. 23
submission-recording endpoint, both of which change what a caller can do to a
tenant's data.

That table's obvious purpose is to let someone enumerate the reachable surface
before an integration or a security review, and it gave no hint that it was
capable of being wrong. Now a drift fails a build.

    python -m scripts.api_surface --check    # CI: exit 1 on drift
    python -m scripts.api_surface            # print the real counts
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
ROUTERS = ROOT / "packages" / "api" / "app" / "routers"
README = ROOT / "README.md"

# A README row: | `/api/v1/thing` | 7 | Purpose |
_ROW = re.compile(r"^\|\s*`(?P<path>[^`]+)`\s*\|\s*(?P<count>\d+)\s*\|")

# Rows the README groups differently from the module layout, or that are not
# router modules at all. Mapping them explicitly is better than teaching the
# parser about every special case: the point is to catch drift in the counts,
# not to re-derive the table's structure.
GROUPED = {
    # acn.py serves three README rows; the table splits it by URL prefix.
    "acn": ("/api/v1/acn-export", "/api/v1/deadlines", "/api/v1/csirt/emergency"),
}
IGNORED_ROWS = {
    "/.well-known/jwks.json",
    "/.well-known/security.txt",
    "/health`, `/health/live`, `/health/ready",
    "/api/v1/mcp",
}
# README row path -> router module, where the names differ.
ROW_TO_MODULE = {
    "/api/v1/audit-logs": "audit",
}


def count_endpoints() -> dict[str, int]:
    """Endpoints per router module, counted from the decorators."""
    counts: dict[str, int] = {}
    for path in sorted(ROUTERS.glob("*.py")):
        if path.name == "__init__.py":
            continue
        counts[path.stem] = len(
            re.findall(r"^@router\.(get|post|put|patch|delete)", path.read_text(), re.M)
        )
    return counts


def readme_rows() -> dict[str, int]:
    rows: dict[str, int] = {}
    for line in README.read_text().splitlines():
        m = _ROW.match(line)
        if m:
            rows[m.group("path")] = int(m.group("count"))
    return rows


def compare() -> list[str]:
    """Rows whose count disagrees with the code. Empty when the table is true."""
    code = count_endpoints()
    problems: list[str] = []

    grouped_total = {
        module: sum(readme_rows().get(row, 0) for row in rows)
        for module, rows in GROUPED.items()
    }
    for module, documented in grouped_total.items():
        actual = code.get(module, 0)
        if documented != actual:
            problems.append(
                f"{module}.py has {actual} endpoints; the README rows for it sum to {documented}"
            )

    for row, documented in readme_rows().items():
        if row in IGNORED_ROWS or any(row in rows for rows in GROUPED.values()):
            continue
        module = ROW_TO_MODULE.get(row, row.rstrip("/").split("/")[-1].replace("-", "_"))
        if module not in code:
            continue
        if code[module] != documented:
            problems.append(
                f"{row} documents {documented} endpoints; {module}.py has {code[module]}"
            )
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="exit 1 on drift")
    args = parser.parse_args()

    code = count_endpoints()
    problems = compare()

    if args.check:
        if problems:
            print("README API-surface table has drifted from the code:\n")
            for p in problems:
                print(f"  - {p}")
            print("\nUpdate the table in README.md, or run without --check to see the counts.")
            return 1
        print(f"README API-surface table matches the code ({sum(code.values())} endpoints).")
        return 0

    print(f"{sum(code.values())} endpoints across {len(code)} routers:\n")
    for module, n in sorted(code.items(), key=lambda kv: -kv[1]):
        print(f"  {n:3}  {module}.py")
    if problems:
        print("\nDrift against README.md:")
        for p in problems:
            print(f"  - {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
