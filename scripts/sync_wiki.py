#!/usr/bin/env python3
# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""Render the GitHub wiki from docs/, and check the published wiki against it.

The wiki was a hand-maintained second copy of the guides and a third and fourth
copy of the REST reference, and it drifted the way second copies do. By
2026-09-08 its deployment pages handed the operator a `DATABASE_URL` on the
bootstrap superuser role — which the API refuses to serve with, so following the
wiki produced a stack that would not start — and its API pages documented six
schedule endpoints under `/api/v1/scan-schedules`, a prefix that has never been
served. Both had been wrong for months, and nothing could have noticed: no test
reads the wiki, and the wiki is not in this repository.

So the wiki stops being a source. Every page is rendered from a file under
docs/, `--check` fails when the published wiki no longer matches what docs would
produce, and `make wiki-sync` republishes it.

    python -m scripts.sync_wiki            # render to a temporary directory
    python -m scripts.sync_wiki --check    # CI: exit 1 when the wiki has drifted
    python -m scripts.sync_wiki --out DIR  # render into DIR
"""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
WIKI_REMOTE = "https://github.com/fabriziosalmi/nis2-public.wiki.git"
REPO_BLOB = "https://github.com/fabriziosalmi/nis2-public/blob/main"

# wiki page name -> source file under docs/.
#
# The Italian page names are the ones the wiki already published, so existing
# links keep resolving. A page with no entry here is not generated, and --check
# reports it as an orphan rather than silently tolerating a stale page.
PAGES: dict[str, str] = {
    # English
    "Getting-Started": "guide/getting-started.md",
    "Configuration": "guide/configuration.md",
    "Deployment": "guide/deployment.md",
    "Secrets-Rotation": "guide/secrets-rotation.md",
    "Usage": "guide/usage.md",
    "Services": "guide/services.md",
    "ACN-Compliance": "guide/acn-compliance.md",
    "API-Reference": "reference/api.md",
    "Architecture": "reference/architecture.md",
    "Scanner-Checks": "reference/scanner-checks.md",
    "NIS2-Compliance-Matrix": "reference/compliance-matrix.md",
    "Governance-Checklist": "governance/checklist.md",
    # Italiano
    "Guida-Rapida": "it/guide/getting-started.md",
    "Configurazione": "it/guide/configuration.md",
    "Distribuzione": "it/guide/deployment.md",
    "Rotazione-Segreti": "it/guide/secrets-rotation.md",
    "Utilizzo": "it/guide/usage.md",
    "Servizi": "it/guide/services.md",
    "Conformita-ACN": "it/guide/acn-compliance.md",
    "Riferimento-API": "it/reference/api.md",
    "Architettura": "it/reference/architecture.md",
    "Controlli-Scanner": "it/reference/scanner-checks.md",
    "Matrice-Conformita-NIS2": "it/reference/compliance-matrix.md",
    "Checklist-Governance": "it/governance/checklist.md",
}

# How Home groups the pages, in the order a reader wants them.
HOME_SECTIONS: list[tuple[str, str, list[str]]] = [
    (
        "English",
        "Guides",
        ["Getting-Started", "Configuration", "Deployment", "Secrets-Rotation",
         "Usage", "Services", "ACN-Compliance"],
    ),
    (
        "English",
        "Reference",
        ["API-Reference", "Architecture", "Scanner-Checks",
         "NIS2-Compliance-Matrix", "Governance-Checklist"],
    ),
    (
        "Italiano",
        "Guide",
        ["Guida-Rapida", "Configurazione", "Distribuzione", "Rotazione-Segreti",
         "Utilizzo", "Servizi", "Conformita-ACN"],
    ),
    (
        "Italiano",
        "Riferimento",
        ["Riferimento-API", "Architettura", "Controlli-Scanner",
         "Matrice-Conformita-NIS2", "Checklist-Governance"],
    ),
]

_LINK = re.compile(r"\[([^\]]*)\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
_WIKILINK = re.compile(r"\[\[([^\]]+)\]\]")


def _source_to_page() -> dict[pathlib.Path, str]:
    return {(DOCS / src).resolve(): page for page, src in PAGES.items()}


def _rewrite_links(body: str, source: pathlib.Path) -> str:
    """Point in-docs links at the corresponding wiki page.

    A relative link that resolves to a generated source becomes a wiki page
    link; one that resolves to a docs file with no wiki page becomes a link into
    the repository, because a dangling wiki link reads as a missing page rather
    than as "this lives elsewhere".
    """
    mapping = _source_to_page()

    def replace(match: re.Match[str]) -> str:
        text, target = match.group(1), match.group(2)
        if target.startswith(("http://", "https://", "#", "mailto:")):
            return match.group(0)
        path, _, anchor = target.partition("#")
        if not path.endswith(".md"):
            return match.group(0)
        resolved = (source.parent / path).resolve()
        suffix = f"#{anchor}" if anchor else ""
        page = mapping.get(resolved)
        if page:
            return f"[{text}]({page}{suffix})"
        try:
            rel = resolved.relative_to(ROOT)
        except ValueError:
            return match.group(0)
        return f"[{text}]({REPO_BLOB}/{rel}{suffix})"

    return _LINK.sub(replace, body)


def render(page: str, source_rel: str) -> str:
    source = (DOCS / source_rel).resolve()
    if not source.exists():
        raise SystemExit(f"sync_wiki: missing source for {page}: docs/{source_rel}")
    body = _rewrite_links(source.read_text(), source)
    if _WIKILINK.search(body):
        raise SystemExit(
            f"sync_wiki: docs/{source_rel} contains [[wiki links]], which mean "
            f"nothing outside the wiki. Use a relative markdown link."
        )
    italian = source_rel.startswith("it/")
    footer = (
        f"*Questa pagina è generata da "
        f"[`docs/{source_rel}`]({REPO_BLOB}/docs/{source_rel}). "
        f"Le modifiche fatte qui vengono sovrascritte: correggi il file sorgente.*"
        if italian
        else f"*This page is generated from "
        f"[`docs/{source_rel}`]({REPO_BLOB}/docs/{source_rel}). "
        f"Edits made here are overwritten — change the source file instead.*"
    )
    return (
        f"<!-- Generated by scripts/sync_wiki.py from docs/{source_rel}. Do not edit here. -->\n"
        f"{body.rstrip()}\n\n---\n\n{footer}\n"
    )


def render_home() -> str:
    lines = [
        "<!-- Generated by scripts/sync_wiki.py. Do not edit here. -->",
        "# NIS2 Compliance Platform",
        "",
        "Open-source NIS2 compliance platform: technical validation, governance",
        "checklist, incident lifecycle under Art. 23, and vendor risk under Art. 18.",
        "",
        "Every page below is generated from `docs/` in the repository. The wiki used",
        "to be maintained by hand and drifted far enough to document a deployment",
        "that would not start, so it is now a rendering of the documentation rather",
        "than a second copy of it.",
        "",
        f"- Repository: {REPO_BLOB.rsplit('/blob/', 1)[0]}",
        "",
    ]
    seen: list[tuple[str, str]] = []
    for language, group, pages in HOME_SECTIONS:
        if (language, group) in seen:
            continue
        seen.append((language, group))
        if not any(lang == language for lang, _ in seen[:-1]):
            lines += [f"## {language}", ""]
        lines += [f"### {group}", ""]
        for page in pages:
            lines.append(f"- [{page.replace('-', ' ')}]({page})")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def generate() -> dict[str, str]:
    pages = {f"{page}.md": render(page, src) for page, src in PAGES.items()}
    pages["Home.md"] = render_home()
    return pages


def write(out: pathlib.Path) -> list[str]:
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for name, content in generate().items():
        (out / name).write_text(content)
        written.append(name)
    return sorted(written)


def check() -> int:
    """Compare the published wiki against what docs/ would render."""
    generated = generate()
    with tempfile.TemporaryDirectory() as tmp:
        clone = pathlib.Path(tmp) / "wiki"
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", WIKI_REMOTE, str(clone)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            # Do not fail the build on an unreachable wiki: that is a network
            # fact, not a documentation defect. Say so loudly instead.
            print("sync_wiki: could not clone the wiki; skipping the comparison.")
            print(f"  {result.stderr.strip().splitlines()[-1] if result.stderr.strip() else ''}")
            return 0

        published = {p.name: p.read_text() for p in clone.glob("*.md")}

    stale = sorted(n for n, c in generated.items() if published.get(n) != c)
    orphans = sorted(set(published) - set(generated))

    if not stale and not orphans:
        print(f"The published wiki matches docs/ ({len(generated)} pages).")
        return 0

    print("The published wiki has drifted from docs/:\n")
    for name in stale:
        state = "differs from" if name in published else "is missing from"
        print(f"  - {name} {state} the published wiki")
    for name in orphans:
        print(f"  - {name} is published but is no longer generated from docs/")
    print("\nRun `make wiki-sync` to republish it from docs/.")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="exit 1 when the published wiki has drifted")
    parser.add_argument("--out", metavar="DIR", help="render the pages into DIR")
    args = parser.parse_args()

    if args.check:
        return check()

    out = pathlib.Path(args.out) if args.out else pathlib.Path(tempfile.mkdtemp(prefix="nis2-wiki-"))
    written = write(out)
    print(f"Rendered {len(written)} pages into {out}:\n")
    for name in written:
        print(f"  {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
