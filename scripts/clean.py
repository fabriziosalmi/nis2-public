#!/usr/bin/env python3
# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
"""Cross-platform cleanup helper for `make clean` / `make clean-all`.

Replaces Unix-only shell idioms (`find -exec`, `2>/dev/null`, `|| true`,
`xargs -r`) with stdlib pathlib so the Makefile works identically on
Linux, macOS, WSL, and Windows cmd.exe. Reported by Davide on
Windows: the `find` and `|| true` calls in the previous Makefile broke
on `cmd.exe` because neither builtin exists there.

Usage:
    python scripts/clean.py            # = make clean (caches only)
    python scripts/clean.py --all      # = make clean-all (also drops
                                       # host node_modules + project
                                       # docker images)
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Directory names to delete recursively. `dirname == DIR_TARGETS[i]` —
# we don't follow symlinks; we don't try to be clever about hidden
# folders. The set is intentionally small.
DIR_TARGETS_CACHE = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
DIR_TARGETS_BUILD = {".next", ".turbo"}


def rmtree(path: Path) -> None:
    """Best-effort recursive delete. On Windows, files in node_modules
    may be locked by the editor's TypeScript server — log and continue
    rather than abort the whole cleanup."""
    try:
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path, ignore_errors=False)
        elif path.exists():
            path.unlink(missing_ok=True)
    except OSError as exc:  # noqa: BLE001 — pathlib raises a few subclasses
        print(f"  skip: {path} ({exc.__class__.__name__}: {exc})", file=sys.stderr)


def find_and_clean(root: Path, names: set[str]) -> int:
    """Walk the tree and remove every directory whose name matches
    `names`. Returns the count for the summary line."""
    count = 0
    # `Path.rglob('*')` would follow into node_modules and waste time;
    # we explicitly prune those branches.
    skip_branches = {"node_modules", ".git", ".venv", "venv"}
    for d in list(root.rglob("*")):
        if d.is_dir() and d.name in names:
            rmtree(d)
            count += 1
        elif d.is_dir() and d.name in skip_branches:
            # Don't descend further into pruned branches. rglob already
            # listed them above, but skipping their *children* is what
            # actually wins us the wall-clock time on a fresh node_modules.
            continue
    return count


def docker_compose_down(file: Path, *, with_volumes: bool) -> None:
    if not file.exists():
        return
    args = ["docker", "compose", "-f", str(file), "down"]
    if with_volumes:
        args.append("-v")
    print(f"  $ {' '.join(args)}")
    # We deliberately ignore non-zero exit: docker may not be running,
    # the stack may already be down. The Makefile target's whole point
    # is that the user can re-run it without thinking.
    subprocess.run(args, check=False)


def remove_project_images() -> None:
    """`docker images | grep ^docker-(api|web|celery|prom) | xargs docker rmi`
    rewritten without the pipe so cmd.exe is happy."""
    try:
        out = subprocess.run(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return
    candidates = [
        line for line in out.stdout.splitlines()
        if line.startswith(("docker-api", "docker-web", "docker-celery", "docker-prom"))
    ]
    if not candidates:
        return
    print(f"  removing {len(candidates)} project images: {', '.join(candidates[:5])}{'...' if len(candidates) > 5 else ''}")
    subprocess.run(["docker", "rmi", "-f", *candidates], check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description="Cross-platform monorepo cleanup")
    parser.add_argument(
        "--all",
        action="store_true",
        help="Nuclear cleanup: drop prod stack volumes, host node_modules, "
        "and project docker images on top of the regular clean.",
    )
    args = parser.parse_args()

    print("== docker compose dev down -v ==")
    docker_compose_down(REPO_ROOT / "infra" / "docker" / "docker-compose.dev.yml", with_volumes=True)

    print("== Python caches ==")
    n = find_and_clean(REPO_ROOT, DIR_TARGETS_CACHE)
    print(f"  removed {n} dir(s)")

    print("== Frontend build caches ==")
    n = find_and_clean(REPO_ROOT, DIR_TARGETS_BUILD)
    print(f"  removed {n} dir(s)")

    if args.all:
        print("== docker compose prod down -v ==")
        docker_compose_down(REPO_ROOT / "infra" / "docker" / "docker-compose.prod.yml", with_volumes=True)

        print("== host node_modules ==")
        nm = REPO_ROOT / "packages" / "web" / "node_modules"
        if nm.exists():
            print(f"  removing {nm}")
            rmtree(nm)
        else:
            print("  (already absent)")

        print("== project docker images ==")
        remove_project_images()

    print("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
