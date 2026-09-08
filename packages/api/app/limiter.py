# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""The application-wide rate limiter.

It used to live in app/routers/auth.py, so eight modules — including
app/main.py, the composition root — imported a 1608-line transport module to
obtain a piece of cross-cutting infrastructure. Three costs followed: main.py
could not be imported without executing the entire authentication router; every
router wanting a rate limit acquired a hard dependency on authentication for a
reason unrelated to authentication; and the dependency graph read as though
`app.routers.assets -> app.routers.auth` were a routing relationship, which it
was not. It was also one edit away from an import cycle, the moment auth.py
needed anything from a router that already imported it.
"""

from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import settings

# Shared through Redis, not per process.
#
# With only a key function slowapi keeps its counters in process memory, and
# production runs four gunicorn workers — so a decorator reading 10/minute
# admitted up to forty requests a minute across the deployment, the effective
# limit moved with the worker count, and restarting the API cleared every
# counter. That last property is the worst of the three: the operational
# response to suspected abuse was also the action that removed the protection.
#
# Redis is already a required dependency of every deployment, so this needs no
# new infrastructure. In-memory remains the fallback when no broker is
# configured, which keeps the unit tests and a bare `python -m app.main` working.
def _limiter_storage_uri() -> str | None:
    uri = (settings.redis_url or "").strip()
    return uri or None


limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=_limiter_storage_uri(),
    # Degrade to per-process counters if Redis becomes unreachable, rather than
    # doing either of the two things a bare Redis backend would do: raise on
    # every rate-limited request, which turns a Redis blip into a total login
    # outage, or swallow the error and stop limiting entirely. In-memory
    # fallback keeps a weaker version of the control running through the
    # outage — which is the same protection this deployment had before, so the
    # failure mode is a return to the previous behaviour rather than a new one.
    in_memory_fallback_enabled=True,
)
