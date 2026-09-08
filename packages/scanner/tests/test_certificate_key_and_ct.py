# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""The certificate analyser measured the wrong things.

Two defects, both of the kind that produce a confident wrong answer rather than
an obvious failure — which is the worst kind for a document an auditor reads.

**The "key strength" was not the certificate's key.** The type was inferred
from the name of the negotiated cipher suite, and TLS 1.3 suite names
("TLS_AES_128_GCM_SHA256") carry no authentication algorithm at all, so every
modern handshake fell through to "Unknown" and the check quietly did nothing —
observed live against github.com, whose certificate is ECDSA. Worse, the size
came from `ssl_object.cipher()[2]`, the SYMMETRIC key length of the session,
and was then compared against RSA thresholds. A TLS 1.2 RSA session with
AES-256 therefore reported **"Weak RSA key: 256 bits"** as a HIGH finding,
about a sound 2048-bit certificate.

**A failed Certificate Transparency lookup read as an absence.** `ct_logged`
defaulted to False and was only ever set True, so a crt.sh timeout or rate
limit — neither rare — became "not present in any Certificate Transparency
log". Every CA-issued certificate since 2018 is logged, so the report
contradicted a public record anyone can check in a browser, and the health
score withheld its CT bonus on the strength of it.
"""

from __future__ import annotations

import datetime

import pytest

from nis2scan.certificate import CertificateAnalyzer, CertificateInfo

cryptography = pytest.importorskip("cryptography")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402


def _self_signed(key) -> bytes:
    """A DER certificate carrying `key`'s public half."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _analyse(der: bytes, cipher_suite: str = "TLS_AES_128_GCM_SHA256") -> CertificateInfo:
    info = CertificateInfo(domain="example.test", port=443)
    info.der = der
    info.cipher_suite = cipher_suite
    CertificateAnalyzer()._analyze_key_strength(info)
    return info


class TestTheKeyComesFromTheCertificate:
    def test_a_tls13_handshake_no_longer_yields_unknown(self):
        """The suite name carries no authentication algorithm, so inference
        from it could only ever return "Unknown" — silently, for most of the
        modern web."""
        info = _analyse(_self_signed(ec.generate_private_key(ec.SECP256R1())))
        assert info.key_type == "ECDSA"
        assert info.key_size == 256

    def test_rsa_size_is_the_certificate_key_not_the_session_cipher(self):
        """The defect that fabricated findings: `cipher()[2]` is the symmetric
        key length, and 256 < 2048 made every AES-256 session a weak RSA key."""
        info = _analyse(
            _self_signed(rsa.generate_private_key(public_exponent=65537, key_size=2048)),
            cipher_suite="ECDHE-RSA-AES256-GCM-SHA384",
        )
        assert info.key_type == "RSA"
        assert info.key_size == 2048
        assert info.key_strength == "ACCEPTABLE"

    def test_a_sound_certificate_raises_no_weak_key_finding(self):
        """The regression in one assertion. This used to be a HIGH finding."""
        info = _analyse(
            _self_signed(rsa.generate_private_key(public_exponent=65537, key_size=2048)),
            cipher_suite="ECDHE-RSA-AES256-GCM-SHA384",
        )
        assert not [f for f in info.findings if "Weak" in f["message"]]

    def test_a_genuinely_weak_key_is_still_caught(self):
        """The check has to keep working, not merely stop lying."""
        info = _analyse(_self_signed(rsa.generate_private_key(public_exponent=65537, key_size=1024)))
        assert info.key_strength == "WEAK"
        weak = [f for f in info.findings if "Weak RSA key" in f["message"]]
        assert weak and weak[0]["severity"] == "HIGH"
        assert "1024 bits" in weak[0]["message"]

    def test_ed25519_is_strong_without_a_size_comparison(self):
        """Fixed-parameter curve: there is no bit count to compare, and
        comparing one against RSA thresholds is how this went wrong before."""
        info = _analyse(_self_signed(ed25519.Ed25519PrivateKey.generate()))
        assert info.key_type == "Ed25519"
        assert info.key_strength == "STRONG"

    def test_no_certificate_means_undetermined_not_a_guess(self):
        info = _analyse(b"")
        assert info.key_strength == "UNDETERMINED"
        assert info.key_type == "Unknown"

    def test_an_unparseable_certificate_means_undetermined(self):
        info = _analyse(b"\x30\x82not-a-certificate")
        assert info.key_strength == "UNDETERMINED"


class TestCertificateTransparencyIsTriState:
    def test_the_default_is_undetermined_not_absent(self):
        """The whole defect. False was both "crt.sh said no" and "crt.sh never
        answered", and the second is the common case."""
        assert CertificateInfo(domain="x", port=443).ct_logged is None

    def test_an_undetermined_lookup_earns_no_score_bonus_and_no_penalty(self):
        analyzer = CertificateAnalyzer()

        undetermined = CertificateInfo(domain="x", port=443)
        undetermined.chain_valid = True
        analyzer._calculate_score(undetermined)

        logged = CertificateInfo(domain="x", port=443)
        logged.chain_valid = True
        logged.ct_logged = True
        analyzer._calculate_score(logged)

        absent = CertificateInfo(domain="x", port=443)
        absent.chain_valid = True
        absent.ct_logged = False
        analyzer._calculate_score(absent)

        assert undetermined.score == absent.score, (
            "an undetermined lookup must not be scored as a confirmed absence"
        )
        assert logged.score >= undetermined.score

    def test_a_failed_lookup_is_reported_rather_than_dropped(self):
        """A check that could not run is not a check that passed; the report
        has to say which."""
        import inspect

        source = inspect.getsource(CertificateAnalyzer._query_ct_logs)
        assert "info.errors.append" in source
        assert "undetermined" in source.lower()


class TestTheObsoleteProtocolProbeCanActuallyFire:
    """The probe annotated its own bare except with the conclusion.

    `pass  # Protocol not supported — good` asserted that a failed handshake
    proved the target refuses TLS 1.0/1.1. On Debian bookworm, the base image
    this ships on, OpenSSL's default security level refuses those versions
    client-side, so the handshake died locally before a byte reached the target
    and the probe returned "clean" for every host on earth. The identical defect
    was diagnosed and fixed in nis2scan/scanner.py; this copy was missed, and a
    server genuinely serving TLS 1.0 scored 100.
    """

    def test_the_probe_offers_a_permissive_cipher_string(self):
        """Without this the local OpenSSL never offers the protocol."""
        assert CertificateAnalyzer._WEAK_PROBE_CIPHERS == "ALL:@SECLEVEL=0"

    def test_an_unavailable_probe_is_recorded_rather_than_read_as_absence(self):
        """The three outcomes must be distinguishable: offered, refused by the
        target, and not asked. The third used to be indistinguishable from the
        second."""
        import inspect

        source = inspect.getsource(CertificateAnalyzer._check_weak_protocols)
        assert "info.errors.append" in source
        assert "undetermined" in source

    def test_the_conclusion_is_no_longer_asserted_in_a_comment(self):
        import inspect

        source = inspect.getsource(CertificateAnalyzer._check_weak_protocols)
        assert "Protocol not supported" not in source

    def test_it_matches_the_sibling_implementation(self):
        """Two copies of a probe is how one of them stayed broken. Until they
        are merged, pin that they agree on the cipher string."""
        from nis2scan.scanner import Scanner

        assert (
            CertificateAnalyzer._WEAK_PROBE_CIPHERS == Scanner._WEAK_PROBE_CIPHERS
        )
