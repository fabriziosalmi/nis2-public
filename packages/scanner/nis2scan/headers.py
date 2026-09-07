# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""Security headers and cookie flags, evaluated rather than counted.

The scanner used to check that a header was *present*. Under that rule

    Content-Security-Policy: default-src *; script-src 'unsafe-inline' 'unsafe-eval'

passes, and so does `Strict-Transport-Security: max-age=1`. A compliance report
that records those as satisfied controls is worse than one that omits them: it
tells a CISO the measure is in place.

Cookie flags were matched as substrings of the raw `Set-Cookie` line, so a
cookie named `secure_session` counted as Secure, and `SameSite=None` — which is
weaker than omitting the attribute in most threat models — was indistinguishable
from `SameSite=Strict`.

Everything here is pure: it takes header strings and returns findings, so it is
testable without a network and cannot be the reason a scan hangs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

# Below this, HSTS is decorative: a browser that has never visited the site is
# unprotected on first contact, and the window is too short to survive a normal
# gap between visits. The RFC 6797 guidance and every major preload list use six
# months as the floor.
HSTS_MIN_MAX_AGE = 15_552_000  # 180 days

CSP_UNSAFE_SOURCES = ("'unsafe-inline'", "'unsafe-eval'")
CSP_WILDCARD_SOURCES = ("*", "http:", "https:", "data:")

# Directives whose absence means the policy does not constrain that resource
# type at all, unless default-src covers it.
CSP_KEY_DIRECTIVES = ("script-src", "object-src", "base-uri", "frame-ancestors")


@dataclass
class HeaderIssue:
    """One problem with one header. `severity` mirrors the finding scale."""

    header: str
    severity: str
    summary: str
    detail: str


@dataclass
class CookieFlags:
    name: str
    secure: bool
    httponly: bool
    samesite: Optional[str]  # "Strict" | "Lax" | "None" | None when absent
    issues: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Cookies
# ---------------------------------------------------------------------------


def parse_set_cookie(raw: str) -> CookieFlags:
    """Parse one Set-Cookie line into its actual attributes.

    Attribute-level, not substring: `secure_session=1` does not set Secure, and
    `SameSite=None` is reported as itself rather than collapsed into "samesite
    present" alongside Strict.
    """
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts else ""

    secure = False
    httponly = False
    samesite: Optional[str] = None
    for attr in parts[1:]:
        key, _, value = attr.partition("=")
        key = key.strip().lower()
        if key == "secure":
            secure = True
        elif key == "httponly":
            httponly = True
        elif key == "samesite":
            samesite = value.strip().title() or None

    flags = CookieFlags(name=name, secure=secure, httponly=httponly, samesite=samesite)
    if not secure:
        flags.issues.append("missing Secure — the cookie can travel over plain HTTP")
    if not httponly:
        flags.issues.append("missing HttpOnly — readable by JavaScript, so an XSS can steal it")
    if samesite is None:
        flags.issues.append("no SameSite attribute — browser defaults vary")
    elif samesite == "None":
        flags.issues.append(
            "SameSite=None — sent on cross-site requests, which is weaker than "
            "omitting the attribute in browsers defaulting to Lax"
        )
    return flags


# ---------------------------------------------------------------------------
# Strict-Transport-Security
# ---------------------------------------------------------------------------


def evaluate_hsts(value: Optional[str]) -> list[HeaderIssue]:
    if not value:
        return [
            HeaderIssue(
                "Strict-Transport-Security", "MEDIUM",
                "HSTS not set",
                "Without HSTS a browser will honour a plain-HTTP link or a downgrade.",
            )
        ]

    issues: list[HeaderIssue] = []
    match = re.search(r"max-age\s*=\s*(\d+)", value, re.I)
    if not match:
        issues.append(
            HeaderIssue(
                "Strict-Transport-Security", "MEDIUM",
                "HSTS has no max-age",
                f"Header present but unusable: {value!r}",
            )
        )
        return issues

    max_age = int(match.group(1))
    if max_age == 0:
        issues.append(
            HeaderIssue(
                "Strict-Transport-Security", "MEDIUM",
                "HSTS max-age is 0",
                "max-age=0 instructs browsers to FORGET the policy — it disables HSTS.",
            )
        )
    elif max_age < HSTS_MIN_MAX_AGE:
        issues.append(
            HeaderIssue(
                "Strict-Transport-Security", "LOW",
                f"HSTS max-age is short ({max_age}s)",
                f"Under the {HSTS_MIN_MAX_AGE}s (180-day) floor; the policy lapses "
                f"between visits and cannot be preloaded.",
            )
        )
    if "includesubdomains" not in value.lower():
        issues.append(
            HeaderIssue(
                "Strict-Transport-Security", "LOW",
                "HSTS does not cover subdomains",
                "Without includeSubDomains a subdomain served over HTTP can set "
                "cookies for the parent domain.",
            )
        )
    return issues


# ---------------------------------------------------------------------------
# Content-Security-Policy
# ---------------------------------------------------------------------------


def _csp_directives(value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for chunk in value.split(";"):
        tokens = chunk.split()
        if tokens:
            directives[tokens[0].lower()] = tokens[1:]
    return directives


def evaluate_csp(value: Optional[str]) -> list[HeaderIssue]:
    """Judge the policy, not its existence.

    `default-src *; script-src 'unsafe-inline'` used to pass as a satisfied
    control. It permits exactly the injection CSP exists to stop.
    """
    if not value:
        return [
            HeaderIssue(
                "Content-Security-Policy", "MEDIUM",
                "No Content-Security-Policy",
                "Nothing constrains where scripts, styles or frames may come from.",
            )
        ]

    issues: list[HeaderIssue] = []
    directives = _csp_directives(value)
    script_sources = directives.get("script-src", directives.get("default-src", []))

    unsafe = [s for s in script_sources if s.lower() in CSP_UNSAFE_SOURCES]
    if unsafe:
        issues.append(
            HeaderIssue(
                "Content-Security-Policy", "HIGH",
                f"CSP allows {', '.join(unsafe)} for scripts",
                "This re-permits inline or dynamically evaluated script, which is "
                "the class of injection CSP is meant to block. Use nonces or hashes.",
            )
        )

    wildcards = [s for s in script_sources if s in CSP_WILDCARD_SOURCES]
    if wildcards:
        issues.append(
            HeaderIssue(
                "Content-Security-Policy", "HIGH",
                f"CSP script sources include the wildcard {', '.join(wildcards)}",
                "Any origin may serve script to this page; the policy constrains nothing.",
            )
        )

    if "default-src" not in directives and "script-src" not in directives:
        issues.append(
            HeaderIssue(
                "Content-Security-Policy", "MEDIUM",
                "CSP sets neither default-src nor script-src",
                f"Script loading is unconstrained. Directives present: "
                f"{', '.join(sorted(directives)) or 'none'}.",
            )
        )

    if "object-src" not in directives and "default-src" not in directives:
        issues.append(
            HeaderIssue(
                "Content-Security-Policy", "LOW",
                "CSP does not restrict object-src",
                "Plugin content (<object>, <embed>) is unconstrained; object-src "
                "'none' is the usual setting.",
            )
        )

    if "frame-ancestors" not in directives:
        issues.append(
            HeaderIssue(
                "Content-Security-Policy", "LOW",
                "CSP does not set frame-ancestors",
                "Clickjacking protection then rests on X-Frame-Options alone, "
                "which CSP supersedes.",
            )
        )
    return issues


# ---------------------------------------------------------------------------


def evaluate_headers(headers: dict) -> list[HeaderIssue]:
    """Evaluate the security headers of one response.

    `headers` is matched case-insensitively, since HTTP header names are.
    """
    lower = {str(k).lower(): v for k, v in (headers or {}).items()}
    issues = evaluate_hsts(lower.get("strict-transport-security"))
    issues += evaluate_csp(lower.get("content-security-policy"))

    xfo = lower.get("x-frame-options")
    if not xfo:
        issues.append(
            HeaderIssue(
                "X-Frame-Options", "LOW",
                "X-Frame-Options not set",
                "Acceptable only when CSP frame-ancestors is set instead.",
            )
        )
    elif xfo.strip().lower() not in ("deny", "sameorigin"):
        issues.append(
            HeaderIssue(
                "X-Frame-Options", "LOW",
                f"X-Frame-Options has an unrecognised value ({xfo!r})",
                "Only DENY and SAMEORIGIN are honoured; ALLOW-FROM was removed "
                "from browsers and is ignored.",
            )
        )

    if not lower.get("x-content-type-options"):
        issues.append(
            HeaderIssue(
                "X-Content-Type-Options", "LOW",
                "X-Content-Type-Options not set",
                "Browsers may MIME-sniff a response into a script.",
            )
        )
    return issues
