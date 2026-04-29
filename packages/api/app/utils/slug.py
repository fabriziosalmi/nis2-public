# Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Slugify helper extracted from `routers/auth.py` in v2.4.18.

The original `_slugify` was a private helper inside the auth router,
called only from `register` (which creates the founder's first org).
With v2.4.18 adding `POST /api/v1/organizations` so users can create
additional orgs from the UI, both routers need the same logic — so
the function moves here.

Behaviour:
  - Lowercase
  - Strip leading/trailing whitespace
  - Drop everything that isn't alphanumeric, whitespace, hyphen, or
    underscore (kills punctuation, accents — note: an org named
    "Société" becomes "socit" which is ugly; that's an existing
    limitation we'd fix with `python-slugify` if it became a real
    pain point, but for now we don't pull in a new dep just for that).
  - Collapse runs of whitespace and underscores into single hyphens
  - Truncate to 128 chars (matches the Organization.slug column type)

The slug returned is **not unique** — both call sites suffix `-1`,
`-2`, ... in a loop until they find a free value, since the slug
column has a UNIQUE index in Postgres.
"""
import re


def slugify(name: str) -> str:
    slug = re.sub(r"[^\w\s-]", "", name.lower().strip())
    slug = re.sub(r"[\s_]+", "-", slug)
    return slug[:128]
