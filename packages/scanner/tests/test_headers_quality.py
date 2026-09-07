# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""Security headers judged on content, cookie flags parsed as attributes.

The scanner checked that a header was PRESENT. Under that rule

    Content-Security-Policy: default-src *; script-src 'unsafe-inline' 'unsafe-eval'

passed as a satisfied control, and so did `Strict-Transport-Security: max-age=1`
and even `max-age=0`, which instructs browsers to forget the policy entirely. A
compliance report recording those as met is worse than one omitting them: it
tells a CISO the measure is in place.

Cookie flags were matched as substrings of the raw Set-Cookie line, so a cookie
named `secure_session` counted as Secure, and `SameSite=None` — sent on
cross-site requests, weaker than omitting the attribute in browsers that default
to Lax — was indistinguishable from `SameSite=Strict`.

Every "passes" case below is a control: without them, an evaluator that flagged
everything would satisfy the negative cases just as well.
"""

from __future__ import annotations

import pytest

from nis2scan.headers import (
    HSTS_MIN_MAX_AGE,
    evaluate_csp,
    evaluate_headers,
    evaluate_hsts,
    parse_set_cookie,
)


def _summaries(issues) -> str:
    return " | ".join(i.summary for i in issues)


class TestHsts:
    def test_a_strong_policy_raises_nothing(self):
        """Control."""
        assert evaluate_hsts("max-age=31536000; includeSubDomains; preload") == []

    def test_absent_is_reported(self):
        assert "not set" in _summaries(evaluate_hsts(None))

    def test_max_age_zero_is_reported(self):
        """max-age=0 DISABLES HSTS. A presence check read it as compliant."""
        issues = evaluate_hsts("max-age=0")
        assert "max-age is 0" in _summaries(issues)

    def test_short_max_age_is_reported(self):
        issues = evaluate_hsts("max-age=60; includeSubDomains")
        assert "short" in _summaries(issues)

    def test_the_floor_is_not_flagged(self):
        """Boundary: exactly the threshold must pass, or the check nags forever."""
        assert evaluate_hsts(f"max-age={HSTS_MIN_MAX_AGE}; includeSubDomains") == []

    def test_missing_includesubdomains_is_reported(self):
        issues = evaluate_hsts("max-age=31536000")
        assert "subdomains" in _summaries(issues).lower()

    def test_header_without_max_age_is_unusable(self):
        assert "no max-age" in _summaries(evaluate_hsts("includeSubDomains"))


class TestCsp:
    def test_a_strict_policy_raises_nothing(self):
        """Control."""
        policy = (
            "default-src 'self'; script-src 'self'; object-src 'none'; "
            "base-uri 'self'; frame-ancestors 'none'"
        )
        assert evaluate_csp(policy) == []

    def test_unsafe_inline_is_reported_as_high(self):
        """The header the platform's own Caddyfile serves, and the exact policy
        a presence check called compliant."""
        issues = evaluate_csp("default-src 'self'; script-src 'self' 'unsafe-inline'")
        assert any(i.severity == "HIGH" and "unsafe-inline" in i.summary for i in issues)

    def test_unsafe_eval_is_reported(self):
        issues = evaluate_csp("script-src 'self' 'unsafe-eval'; frame-ancestors 'none'")
        assert "unsafe-eval" in _summaries(issues)

    def test_wildcard_script_source_is_reported(self):
        issues = evaluate_csp("default-src *; frame-ancestors 'none'")
        assert any(i.severity == "HIGH" and "wildcard" in i.summary for i in issues)

    def test_absent_is_reported(self):
        assert "No Content-Security-Policy" in _summaries(evaluate_csp(None))

    def test_script_src_falls_back_to_default_src(self):
        """A policy setting only default-src still constrains scripts, and must
        not be reported as leaving script-src unset."""
        issues = evaluate_csp("default-src 'self'; frame-ancestors 'none'; object-src 'none'")
        assert "neither default-src nor script-src" not in _summaries(issues)

    def test_missing_frame_ancestors_is_reported(self):
        issues = evaluate_csp("default-src 'self'; object-src 'none'")
        assert "frame-ancestors" in _summaries(issues)


class TestCookieAttributes:
    def test_a_hardened_cookie_raises_nothing(self):
        """Control."""
        flags = parse_set_cookie("sid=abc; Path=/; Secure; HttpOnly; SameSite=Strict")
        assert flags.issues == []
        assert (flags.secure, flags.httponly, flags.samesite) == (True, True, "Strict")

    def test_a_cookie_named_secure_does_not_set_secure(self):
        """The substring bug, stated directly: `'secure' in raw.lower()` was
        true for this cookie, which has no Secure attribute at all."""
        flags = parse_set_cookie("secure_session=abc; Path=/; HttpOnly")
        assert flags.secure is False
        assert any("Secure" in i for i in flags.issues)

    def test_a_cookie_named_httponly_does_not_set_httponly(self):
        flags = parse_set_cookie("httponly_pref=1; Path=/; Secure")
        assert flags.httponly is False

    def test_samesite_none_is_distinguished_from_strict(self):
        """Both matched `'samesite' in raw.lower()`, so the weaker setting was
        recorded as equivalent to the strongest one."""
        none = parse_set_cookie("sid=a; Secure; HttpOnly; SameSite=None")
        strict = parse_set_cookie("sid=a; Secure; HttpOnly; SameSite=Strict")
        assert none.samesite == "None"
        assert strict.samesite == "Strict"
        assert none.issues and not strict.issues

    def test_attribute_case_is_ignored(self):
        flags = parse_set_cookie("sid=a; SECURE; httponly; samesite=lax")
        assert (flags.secure, flags.httponly, flags.samesite) == (True, True, "Lax")

    def test_the_cookie_name_is_captured(self):
        assert parse_set_cookie("session_id=xyz; Secure").name == "session_id"


class TestEvaluateHeaders:
    def test_header_names_are_matched_case_insensitively(self):
        """HTTP header names are case-insensitive and servers differ; a
        case-sensitive lookup would report a well-configured host as bare."""
        strong = {
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": (
                "default-src 'self'; script-src 'self'; object-src 'none'; "
                "frame-ancestors 'none'"
            ),
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
        }
        assert evaluate_headers(strong) == []
        upper = {k.upper(): v for k, v in strong.items()}
        assert evaluate_headers(upper) == []

    def test_a_bare_response_reports_every_header(self):
        summaries = _summaries(evaluate_headers({}))
        for expected in ("HSTS", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"):
            assert expected in summaries

    @pytest.mark.parametrize("value", ["ALLOW-FROM https://x.example", "allowall", "1"])
    def test_unrecognised_x_frame_options_is_reported(self, value: str):
        """ALLOW-FROM was removed from browsers; a value present but ignored is
        the presence-check failure mode in miniature."""
        issues = evaluate_headers({"x-frame-options": value})
        assert "unrecognised" in _summaries(issues)

    def test_none_headers_do_not_raise(self):
        assert evaluate_headers(None) != []


class TestDnssecRequiresDelegation:
    """A DNSKEY in the zone is not DNSSEC.

    Without a DS record in the PARENT zone there is no chain of trust: resolvers
    ignore the signatures and the zone is unprotected. Signed-but-undelegated is
    the most common DNSSEC misconfiguration, and inferring "enabled" from a
    DNSKEY reported precisely that case as compliant — under Art. 21(2)(h), on a
    control an auditor may well check independently.
    """

    def _dns(self, monkeypatch, *, dnskey: bool, ds: bool):
        import dns.resolver

        from nis2scan.config import Config, Targets
        from nis2scan.scanner import Scanner

        def fake_resolve(name, rdtype, *a, **kw):
            if rdtype == "DNSKEY":
                if dnskey:
                    return ["key"]
                raise dns.resolver.NoAnswer()
            if rdtype == "DS":
                if ds:
                    return ["ds"]
                raise dns.resolver.NoAnswer()
            raise dns.resolver.NoAnswer()

        monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)
        scanner = Scanner(Config(targets=Targets(ip_ranges=["127.0.0.1"]), features={}))
        return scanner.check_dns_security_sync("example.test")

    def test_signed_and_delegated_is_enabled(self, monkeypatch):
        r = self._dns(monkeypatch, dnskey=True, ds=True)
        assert r["dnssec_enabled"] is True

    def test_signed_but_not_delegated_is_not_enabled(self, monkeypatch):
        """The regression: this used to report DNSSEC as enabled."""
        r = self._dns(monkeypatch, dnskey=True, ds=False)
        assert r["dnssec_dnskey"] is True
        assert r["dnssec_ds"] is False
        assert r["dnssec_enabled"] is False, (
            "a signed zone with no DS in the parent has no chain of trust; "
            "resolvers ignore the signatures"
        )

    def test_delegated_without_a_key_is_not_enabled(self, monkeypatch):
        r = self._dns(monkeypatch, dnskey=False, ds=True)
        assert r["dnssec_enabled"] is False

    def test_unsigned_is_not_enabled(self, monkeypatch):
        r = self._dns(monkeypatch, dnskey=False, ds=False)
        assert r["dnssec_enabled"] is False

