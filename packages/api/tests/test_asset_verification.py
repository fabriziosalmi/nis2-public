# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""Nothing may be scanned without established authority over it.

There was no ownership check anywhere. Any authenticated user could add any
domain — or a /16, which the validator permits — as an asset and have the
platform port-scan it, attempt zone transfers against its nameservers, and
request /.env and /.git/HEAD from it. At the /16 ceiling that is roughly 900,000
TCP connections per scan, at ten scans a minute, and in the target's logs it is
indistinguishable from reconnaissance.

The only control that shipped was a legal disclaimer persisted in localStorage
on the public landing page, explicitly suppressed for authenticated users: shown
to people who cannot scan, hidden from those who can.

Three code paths reach a scan, and a gate on one of them is not a gate:

    POST /scans                 the manual path
    scheduled scan task         unattended, on a cron
    MCP scan_target             the most permissive — a free-form target, not
                                even an Asset row

These tests pin all three, plus the verification logic itself. The `legacy`
status is deliberate and tested: assets predating verification keep working,
because an upgrade that silently stopped every existing customer's scans would
be its own defect.
"""

from __future__ import annotations

import inspect

import pytest

from app.utils import asset_verification as verify


class TestChallengeShape:
    def test_a_token_is_not_guessable(self):
        assert len(verify.new_token()) == 64  # 32 bytes, hex
        assert verify.new_token() != verify.new_token()

    def test_the_record_sits_on_a_dedicated_subdomain(self):
        """Not the apex: verification must never collide with SPF, DMARC or a
        site-verification record the customer already depends on."""
        name, value = verify.challenge_record("example.com", "abc123")
        assert name == "_nis2-challenge.example.com"
        assert value == "nis2-verification=abc123"

    def test_the_value_carries_the_token(self):
        _, value = verify.challenge_record("example.com", "deadbeef")
        assert "deadbeef" in value


class TestWhichTargetsCanBeProven:
    def test_domains_use_dns(self):
        assert verify.requires_dns_proof("domain") is True

    @pytest.mark.parametrize("target_type", ["ip", "cidr"])
    def test_addresses_cannot(self, target_type: str):
        """An address range has no DNS to prove anything with. RDAP would say
        who it is allocated to, not whether this customer is authorised by
        them, so it cannot close the question either."""
        assert verify.requires_dns_proof(target_type) is False


class TestTheScanGate:
    @pytest.mark.parametrize("status", [verify.VERIFIED, verify.ATTESTED])
    def test_established_authority_may_scan(self, status: str):
        assert verify.may_scan(status) is True

    def test_legacy_assets_are_grandfathered(self):
        """Assets created before verification existed keep working. An upgrade
        that silently stopped every existing customer's scans would be its own
        defect; they are shown as unverified everywhere else instead."""
        assert verify.may_scan(verify.LEGACY) is True

    def test_unverified_may_not_scan(self):
        """The point of the whole module."""
        assert verify.may_scan(verify.UNVERIFIED) is False

    def test_an_unknown_status_may_not_scan(self):
        """Fail closed: a status this code does not recognise — a typo, a
        half-finished migration — must not become permission."""
        assert verify.may_scan("something-else") is False
        assert verify.may_scan(None) is False


class TestEveryPathIsGated:
    """A gate on one of three paths is not a gate.

    Structural rather than behavioural: exercising the scheduled task and the
    MCP dispatch end to end needs a database and a Celery broker, while what
    actually went wrong is a call site being forgotten. These fail if one is.
    """

    def test_the_manual_scan_path_checks_it(self):
        from app.routers import scans

        source = inspect.getsource(scans.create_scan)
        assert "asset_verification.may_scan" in source, (
            "POST /scans does not check verification_status"
        )
        assert "403" in source or "HTTP_403_FORBIDDEN" in source

    def test_the_scheduled_scan_path_checks_it(self):
        """Unattended and on a cron — the worst shape for an unauthorised scan.
        A schedule created before verification, or pointing at an asset whose
        proof was later revoked, must not keep running."""
        from app.tasks import scan_tasks

        source = inspect.getsource(scan_tasks)
        assert "asset_verification.may_scan" in source, (
            "the scheduled scan task resolves assets on its own and does not "
            "check verification_status"
        )

    def test_the_mcp_tool_checks_it(self):
        from app.mcp_server import handle_tool_call

        source = inspect.getsource(handle_tool_call)
        assert "_require_owned_target" in source, (
            "MCP scan_target takes a free-form target and is the most permissive "
            "of the three paths; without this it is the way around the other two"
        )

    @pytest.mark.asyncio
    async def test_the_mcp_tool_refuses_without_a_session(self):
        """The STDIO entry point has no database session. Refusing is the only
        honest answer — running the scan would mean scanning an arbitrary host
        with no record of who authorised it."""
        from app.mcp_server import _require_owned_target

        error = await _require_owned_target("example.com", db=None, org_id=None)
        assert error and "authenticated session" in error


class TestAttestationIsNotAShortcut:
    def test_a_domain_cannot_be_attested(self):
        """Domains have DNS proof. An attestation must never be the easy way
        around evidence that exists — otherwise nobody would ever publish the
        record."""
        from app.routers import assets

        source = inspect.getsource(assets.attest_authority)
        assert "requires_dns_proof" in source
        assert "use verification/start" in source

    def test_attestation_is_admin_only(self):
        from app.routers import assets

        # The decorator sits above the function, so read the module around it.
        module_source = inspect.getsource(assets)
        idx = module_source.index("async def attest_authority")
        decorator = module_source[max(0, idx - 400):idx]
        assert 'require_role("admin")' in decorator, (
            "asserting authority over an address range is not an auditor action"
        )

    def test_the_statement_is_required_and_recorded(self):
        """An attestation nobody had to type is not an attestation."""
        from app.routers.assets import AttestationRequest

        field = AttestationRequest.model_fields["statement"]
        assert field.is_required()
        source = inspect.getsource(
            __import__("app.routers.assets", fromlist=["x"]).attest_authority
        )
        assert "payload.statement" in source, "the wording is not recorded anywhere"
