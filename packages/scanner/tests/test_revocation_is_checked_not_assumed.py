# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""Revocation was never checked, and the report said GOOD anyway.

`_check_ocsp` opened a second TLS connection, looked for an OCSP responder URL
in the certificate, and — if it found one — set `ocsp_status = "GOOD"`. The
presence of a URL was read as the answer that URL would have given. No OCSP
request was ever made, no response was ever verified, and a revoked
certificate was reported as good in a document an auditor reads.

A revocation answer is only worth having if it was checked: the response must
be signed by the issuer or a delegate it authorised, must name this
certificate, and must be current. That is a small PKI client, and CertMate
carries one. So the scanner asks CertMate when one is configured, and
otherwise says UNKNOWN and why. It never infers.
"""
import asyncio

import pytest

from nis2scan import certificate as certmod
from nis2scan.certificate import CertificateAnalyzer, CertificateInfo


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def no_ambient_certmate(monkeypatch):
    """The machine running the tests may have a CertMate configured."""
    monkeypatch.delenv("CERTMATE_URL", raising=False)
    monkeypatch.delenv("CERTMATE_TOKEN", raising=False)


class _Client:
    """A CertMate that answers with whatever the test hands it."""

    def __init__(self, answer=None, raises=None):
        self.answer = answer
        self.raises = raises
        self.calls = []

    def probe(self, host, port=443, check_revocation=True, **kwargs):
        self.calls.append((host, port, check_revocation))
        if self.raises:
            raise self.raises
        return self.answer


def _info(domain="example.com"):
    return CertificateInfo(domain=domain, port=443)


def _with_client(monkeypatch, client):
    monkeypatch.setattr(certmod, "_certmate_client", lambda: client)


# --------------------------------------------------------------------------- #
# What it no longer does
# --------------------------------------------------------------------------- #

def test_a_responder_url_alone_is_not_an_answer(monkeypatch):
    """The defect, stated as a test: a certificate that names an OCSP
    responder says nothing about whether it was revoked."""
    _with_client(monkeypatch, None)
    info = _info()
    info.ocsp_url = "http://ocsp.example-ca.org"
    _run(CertificateAnalyzer()._check_revocation(info))
    assert info.ocsp_status == "UNKNOWN"


def test_without_a_certmate_it_says_what_is_missing(monkeypatch):
    _with_client(monkeypatch, None)
    info = _info()
    _run(CertificateAnalyzer()._check_revocation(info))
    assert info.ocsp_status == "UNKNOWN"
    assert "CERTMATE_URL" in info.revocation_detail


def test_the_source_is_not_configured_by_accident(monkeypatch):
    """Both halves are required. A URL with no token would build a client that
    gets 401 on every probe and reports UNKNOWN for a reason nobody outside
    can see.

    Asserted on the config rather than the client, so the rule is checked even
    where certmate-sdk is not installed — otherwise a missing SDK makes every
    configuration look equally absent."""
    monkeypatch.setenv("CERTMATE_URL", "https://certmate.example.com")
    assert certmod._certmate_config() is None
    monkeypatch.delenv("CERTMATE_URL")
    monkeypatch.setenv("CERTMATE_TOKEN", "t")
    assert certmod._certmate_config() is None
    monkeypatch.setenv("CERTMATE_URL", " https://certmate.example.com ")
    assert certmod._certmate_config() == ("https://certmate.example.com", "t")


# --------------------------------------------------------------------------- #
# What it does instead
# --------------------------------------------------------------------------- #

def test_a_verified_good_answer_is_reported_as_good(monkeypatch):
    client = _Client({"revocation": {"status": "good", "method": "ocsp"}})
    _with_client(monkeypatch, client)
    info = _info()
    _run(CertificateAnalyzer()._check_revocation(info))
    assert info.ocsp_status == "GOOD"
    assert info.revocation_source == "ocsp"
    assert client.calls == [("example.com", 443, True)]


def test_a_revoked_certificate_is_reported_as_revoked(monkeypatch):
    _with_client(monkeypatch, _Client(
        {"revocation": {"status": "revoked", "method": "crl", "reason": "key_compromise"}}))
    info = _info()
    _run(CertificateAnalyzer()._check_revocation(info))
    assert info.ocsp_status == "REVOKED"
    assert "key_compromise" in info.revocation_detail


@pytest.mark.parametrize("status, error", [
    ("unavailable", "the responder answered TRY_LATER"),
    ("unknown", "the responder does not know this certificate"),
    ("not_applicable", None),
])
def test_an_answer_nobody_could_verify_is_unknown(monkeypatch, status, error):
    """CertMate reports `unavailable` when it could not establish revocation.
    Reading that as GOOD would put the old defect back, one layer further
    away."""
    _with_client(monkeypatch, _Client({"revocation": {"status": status, "error": error}}))
    info = _info()
    _run(CertificateAnalyzer()._check_revocation(info))
    assert info.ocsp_status == "UNKNOWN"
    if error:
        assert info.revocation_detail == error


def test_a_certmate_that_cannot_be_reached_is_unknown(monkeypatch):
    _with_client(monkeypatch, _Client(raises=ConnectionError("refused")))
    info = _info()
    _run(CertificateAnalyzer()._check_revocation(info))
    assert info.ocsp_status == "UNKNOWN"
    assert "ConnectionError" in info.revocation_detail


def test_an_answer_without_a_revocation_block_is_unknown(monkeypatch):
    """An older CertMate, or `check_revocation: false`: the key is absent."""
    _with_client(monkeypatch, _Client({"status": "ok", "certificate": {}}))
    info = _info()
    _run(CertificateAnalyzer()._check_revocation(info))
    assert info.ocsp_status == "UNKNOWN"


# --------------------------------------------------------------------------- #
# What the report carries
# --------------------------------------------------------------------------- #

def test_the_report_says_where_the_answer_came_from(monkeypatch):
    _with_client(monkeypatch, _Client({"revocation": {"status": "good", "method": "crl"}}))
    info = _info()
    _run(CertificateAnalyzer()._check_revocation(info))
    report = CertificateAnalyzer().to_dict(info)
    assert report["ocsp"]["status"] == "GOOD"
    assert report["ocsp"]["source"] == "crl"


def test_an_unknown_status_carries_its_reason_into_the_report(monkeypatch):
    _with_client(monkeypatch, None)
    info = _info()
    _run(CertificateAnalyzer()._check_revocation(info))
    report = CertificateAnalyzer().to_dict(info)
    assert report["ocsp"]["status"] == "UNKNOWN"
    assert "CERTMATE_URL" in report["ocsp"]["detail"]
