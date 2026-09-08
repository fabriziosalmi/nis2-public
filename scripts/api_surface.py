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


# Routers documented under a row whose name does not derive from the module, or
# deliberately outside the table. Listed so that "no row" means "undocumented"
# rather than "named differently".
MODULES_WITHOUT_OWN_ROW = {
    "health",   # documented as the `/health`, `/health/live`, `/health/ready` row
    "jwks",     # documented as `/.well-known/jwks.json`
}


def compare() -> list[str]:
    """Everything wrong with the table. Empty when it is true.

    Two kinds of drift, because the first fix for this caught only one of them:
    a row whose count is stale, and a router with no row at all. The counts were
    corrected and the table still omitted notifications, reports, schedules and
    metrics — fourteen endpoints, the same size of gap as before, invisible to a
    checker that only compared the rows that happened to exist.
    """
    code = count_endpoints()
    problems: list[str] = []

    documented_modules = set(MODULES_WITHOUT_OWN_ROW)
    for row in readme_rows():
        for module, rows in GROUPED.items():
            if row in rows:
                documented_modules.add(module)
        documented_modules.add(
            ROW_TO_MODULE.get(row, row.rstrip("/").split("/")[-1].replace("-", "_"))
        )
    for module, n in sorted(code.items()):
        if n and module not in documented_modules:
            problems.append(
                f"{module}.py has {n} endpoint(s) and no row in the README table"
            )

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


REFERENCE = ROOT / "docs" / "reference" / "api.md"

# A reference-doc row: | GET | `/api/v1/thing/{id}` | Description | Auth |
_REF_ROW = re.compile(r"^\|\s*(?P<method>GET|POST|PUT|PATCH|DELETE)\s*\|\s*`(?P<path>[^`]+)`")

# Endpoints deliberately absent from the reference. Each needs a reason, because
# an exemption list is how a coverage check quietly stops covering anything.
REFERENCE_EXEMPT = {
    # Served for machines, documented in README and SECURITY.md rather than in
    # the REST reference an integrator reads.
    ("GET", "/metrics"),
    ("GET", "/.well-known/jwks.json"),
}


def _normalise(path: str) -> str:
    """Compare paths without caring what a path parameter is called."""
    return re.sub(r"\{[^}]*\}", "{}", path.rstrip("/")) or "/"


def code_endpoints() -> set[tuple[str, str]]:
    """(METHOD, path) for every route the API mounts."""
    endpoints: set[tuple[str, str]] = set()
    main = (ROOT / "packages" / "api" / "app" / "main.py").read_text()
    for path in sorted(ROUTERS.glob("*.py")):
        if path.name == "__init__.py":
            continue
        src = path.read_text()
        # A router without prefix= is still mounted; skipping it would have made
        # this check blind to acn.py, jwks.py and metrics.py — six endpoints,
        # including the whole ACN export surface. An empty prefix is a prefix.
        m = re.search(r'APIRouter\((?:[^)]*?)prefix="([^"]*)"', src, re.S)
        router_prefix = m.group(1) if m else ""
        # Routers are mounted under /api/v1 except the two that must sit at the
        # root: /metrics for the Prometheus scraper and the JWKS well-known URL.
        mount = "/api/v1"
        if re.search(rf'include_router\(\s*{path.stem}[\w.]*,\s*prefix=""', main):
            mount = ""
        for method, route in re.findall(
            r'^@router\.(get|post|put|patch|delete)\(\s*\n?\s*"([^"]*)"', src, re.M
        ):
            endpoints.add((method.upper(), _normalise(mount + router_prefix + route)))
    return endpoints


def reference_endpoints() -> set[tuple[str, str]]:
    endpoints: set[tuple[str, str]] = set()
    for line in REFERENCE.read_text().splitlines():
        m = _REF_ROW.match(line)
        if m:
            endpoints.add((m.group("method"), _normalise(m.group("path"))))
    return endpoints


def compare_reference() -> list[str]:
    """Endpoints the code serves and the REST reference does not describe.

    The README table counts endpoints per router; it cannot notice that a
    documented *path* is wrong or missing. docs/reference/api.md was missing
    sixteen — the whole notification-channels router, the TOTP enrolment flow
    and the GDPR export among them — and the published wiki documented six
    schedule endpoints under `/api/v1/scan-schedules`, a prefix the API has
    never served. Counts were green throughout.
    """
    exempt = {(m, _normalise(p)) for m, p in REFERENCE_EXEMPT}
    missing = code_endpoints() - reference_endpoints() - exempt
    return [
        f"{method} {path} is served but absent from docs/reference/api.md"
        for method, path in sorted(missing, key=lambda e: (e[1], e[0]))
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="exit 1 on drift")
    args = parser.parse_args()

    code = count_endpoints()
    problems = compare() + compare_reference()

    if args.check:
        if problems:
            print("The documented API surface has drifted from the code:\n")
            for p in problems:
                print(f"  - {p}")
            print("\nUpdate README.md and/or docs/reference/api.md, or run without --check to see the counts.")
            return 1
        print(f"README table and docs/reference/api.md match the code ({sum(code.values())} endpoints).")
        return 0

    print(f"{sum(code.values())} endpoints across {len(code)} routers:\n")
    for module, n in sorted(code.items(), key=lambda kv: -kv[1]):
        print(f"  {n:3}  {module}.py")
    if problems:
        print("\nDrift against the docs:")
        for p in problems:
            print(f"  - {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
