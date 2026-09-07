# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""Proof that the organisation may scan a target.

There was none. Any authenticated user could add any domain or a /16 as an
Asset and run a port scan, AXFR attempts against the target's nameservers, and
requests for `/.env` and `/.git/HEAD` — up to ~900,000 TCP connections per scan,
at ten scans a minute. The only control shipped was a legal disclaimer in
localStorage on the public landing page, explicitly suppressed for logged-in
users: shown to people who cannot scan, hidden from those who can.

That makes the operator responsible for unauthorised scanning of third parties
the moment the instance has more than one user — which is the deployment this
platform is sold for ("NIS2 consultants and DPO-as-a-service managing multiple
clients"). In Italy and much of the EU unauthorised port scanning carries at
least civil exposure, and an AXFR attempt plus a request for /.env is
indistinguishable from reconnaissance in the target's logs.

Two methods, because one does not fit both shapes of target:

  DNS TXT      For domains. The same mechanism as Let's Encrypt's DNS-01 and
               Search Console: publish a token only someone with control of the
               zone can publish. It is evidence, not an assertion.

  Attestation  For IP addresses and CIDR ranges, which have no DNS to prove
               anything with. RDAP would tell us who an address is allocated to,
               not whether this customer is authorised by them, so it cannot
               close the question either. What remains is a recorded, attributed
               statement: a named user asserts authority on a specific date, and
               the audit log keeps it. That does not stop misuse — nothing here
               can — but it moves the record from "the platform allowed it" to
               "this person asserted it", which is the difference that matters
               when someone has to answer for a scan.
"""

from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass
from typing import Optional

# Where the token is published. A dedicated subdomain rather than the apex, so
# verification never collides with SPF, DMARC or a site-verification record the
# customer already depends on.
CHALLENGE_PREFIX = "_nis2-challenge"
# Named for what it is — the prefix of the record VALUE — rather than "token".
# As TOKEN_PREFIX it tripped gitleaks' generic-api-key rule, which reacts to a
# variable named *TOKEN* assigned a string, and turned the secret-scanning job
# red. The rule was right to be suspicious and the name was simply wrong: this
# is a fixed public marker, not a credential. Renaming removes the false
# positive at the root instead of adding an allowlist entry that would weaken
# the scan for everything else in this file.
CHALLENGE_VALUE_PREFIX = "nis2-verification="

# Statuses stored on the asset.
UNVERIFIED = "unverified"
VERIFIED = "verified"      # DNS TXT proof observed
ATTESTED = "attested"      # a named user asserted authority (IP / CIDR)
LEGACY = "legacy"          # predates verification — see the migration note below


def new_token() -> str:
    """A challenge token. 32 bytes of urandom, hex-encoded."""
    return secrets.token_hex(32)


def challenge_record(domain: str, token: str) -> tuple[str, str]:
    """The DNS record the customer must publish: (name, value)."""
    return f"{CHALLENGE_PREFIX}.{domain}", f"{CHALLENGE_VALUE_PREFIX}{token}"


@dataclass
class VerificationResult:
    ok: bool
    detail: str
    observed: list[str]


async def check_dns_challenge(domain: str, token: str) -> VerificationResult:
    """Look for the challenge TXT record on `domain`.

    Runs the blocking resolver in a thread: this is called from a request
    handler, and a DNS lookup against an unresponsive nameserver would otherwise
    stall the event loop for the resolver's full timeout.
    """
    import dns.resolver

    name, expected = challenge_record(domain, token)

    def _resolve() -> list[str]:
        resolver = dns.resolver.Resolver()
        # A customer who has just published the record should not be told it is
        # absent because a slow nameserver took eight seconds.
        resolver.timeout = 5
        resolver.lifetime = 10
        answers = resolver.resolve(name, "TXT")
        values: list[str] = []
        for record in answers:
            # A TXT record can be split into several strings; the wire format
            # concatenates them, and a token longer than 255 bytes would arrive
            # split. Join before comparing.
            parts = [
                s.decode("utf-8", "ignore") if isinstance(s, bytes) else str(s)
                for s in record.strings
            ]
            values.append("".join(parts).strip())
        return values

    try:
        observed = await asyncio.to_thread(_resolve)
    except Exception as exc:  # dns.resolver raises a family of these
        return VerificationResult(
            ok=False,
            detail=(
                f"No TXT record found at {name}. Publish it and try again; DNS "
                f"changes can take a few minutes to propagate. ({type(exc).__name__})"
            ),
            observed=[],
        )

    if expected in observed:
        return VerificationResult(True, f"Token confirmed at {name}.", observed)

    return VerificationResult(
        ok=False,
        detail=(
            f"{name} exists but none of its values match the expected token. "
            f"Check for a stale record from a previous attempt."
        ),
        observed=observed,
    )


def requires_dns_proof(target_type: str) -> bool:
    """Only domains can be proven with DNS."""
    return target_type == "domain"


def may_scan(status: Optional[str]) -> bool:
    """Whether an asset in this state may be scanned.

    LEGACY is accepted deliberately. Assets predating verification are
    grandfathered rather than silently blocked — an upgrade that made every
    existing customer's scans start failing with no warning would be its own
    kind of defect — but they carry a distinct status, are surfaced as
    unverified in the UI, and can be tightened by an operator who wants the
    stricter posture.
    """
    return status in (VERIFIED, ATTESTED, LEGACY)
