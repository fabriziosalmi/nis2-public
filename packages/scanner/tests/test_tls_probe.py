# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""check_tls, against real TLS servers rather than mocks.

Everything this file covers was previously either wrong or undetectable, and a
mock would have reproduced the wrongness happily:

  * **No SNI.** `open_connection(...)` was called with no `server_hostname` and
    `check_hostname=False`, so no SNI reached the server. Against any shared IP,
    CDN or load balancer the server answers with its DEFAULT certificate, and
    every conclusion drawn was about a different site. The scan pins the
    resolved IP as a DNS-rebinding defence, so the hostname has to travel in the
    handshake or it travels nowhere.

  * **`valid` meant "a handshake completed".** The context used
    `CERT_OPTIONAL` with `check_hostname=False`, so a self-signed certificate
    and a properly chained one were indistinguishable — and the field was named
    `valid` and consumed as a security property.

  * **The obsolete-protocol probe could never fire.** Debian bookworm, the base
    image this ships on, sets OpenSSL's default security level to 2, which
    refuses TLS 1.0/1.1 client-side regardless of `minimum_version`. Verified
    inside the running container: the handshake dies with NO_CIPHERS_AVAILABLE
    before a byte reaches the target, the bare `except` swallowed it, and
    `weak_versions` came back empty for every host — including ones genuinely
    serving TLS 1.0. A probe that cannot fail reports "clean".

These tests stand up actual TLS servers because that last defect is invisible to
any test that does not perform a handshake.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import subprocess
import tempfile
import threading
from pathlib import Path

import pytest

from nis2scan.config import Config, Targets
from nis2scan.scanner import Scanner


# ---------------------------------------------------------------------------
# A throwaway TLS server
# ---------------------------------------------------------------------------


def _self_signed(tmp: Path, cn: str) -> tuple[str, str]:
    key, crt = tmp / "k.pem", tmp / "c.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(crt), "-days", "1", "-subj", f"/CN={cn}"],
        check=True, capture_output=True,
    )
    return str(crt), str(key)


class TlsServer:
    """Serves one handshake at a fixed protocol version, then stops."""

    def __init__(self, cert: str, key: str, *, version: ssl.TLSVersion | None = None):
        self.cert, self.key, self.version = cert, key, version
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert, self.key)
        if self.version is not None:
            ctx.minimum_version = self.version
            ctx.maximum_version = self.version
            try:
                # The server must be permitted to offer the obsolete protocol,
                # or the test would be measuring the server's limits rather than
                # the scanner's.
                ctx.set_ciphers("ALL:@SECLEVEL=0")
            except ssl.SSLError:
                pytest.skip("this OpenSSL build cannot serve the obsolete protocol")
        return ctx

    def _serve(self) -> None:
        ctx = self._context()
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                with ctx.wrap_socket(conn, server_side=True):
                    pass
            except Exception:
                pass

    def __enter__(self) -> "TlsServer":
        self._thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


@pytest.fixture
def scanner(monkeypatch) -> Scanner:
    """A scanner that will probe the ephemeral port the test server binds.

    check_tls only probes Scanner.TLS_PORTS (443, 8443). Widening it here rather
    than binding the servers to 443 keeps the suite runnable without root, and
    leaves the production port list untouched.
    """
    inst = Scanner(Config(targets=Targets(ip_ranges=["127.0.0.1"]), features={}))
    monkeypatch.setattr(Scanner, "TLS_PORTS", tuple(range(1024, 65536)), raising=True)
    return inst


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------


class TestChainValidationIsReal:
    def test_self_signed_is_reported_as_untrusted(self, scanner, tmp_path):
        """The defect in one assertion: this used to come back `valid: True`."""
        cert, key = _self_signed(tmp_path, "localhost")
        with TlsServer(cert, key) as srv:
            result = _run(scanner.check_tls("127.0.0.1", srv.port, "localhost"))
        assert result["handshake_ok"] is True, result
        assert result["chain_valid"] is False, (
            "a self-signed certificate must not validate; the previous "
            "implementation used CERT_OPTIONAL and reported it as valid"
        )
        assert result["chain_error"]

    def test_the_negotiated_version_is_still_reported(self, scanner, tmp_path):
        """An untrusted chain is a finding, not a reason to learn nothing."""
        cert, key = _self_signed(tmp_path, "localhost")
        with TlsServer(cert, key) as srv:
            result = _run(scanner.check_tls("127.0.0.1", srv.port, "localhost"))
        assert result["version"].startswith("TLS")
        assert result.get("cipher")

    def test_a_chain_fault_leaves_the_hostname_undetermined(self, scanner, tmp_path):
        """OpenSSL stops at the first fault.

        A self-signed certificate for another name fails as self-signed; the
        hostname is never examined. An earlier revision inferred "hostname is
        fine" from "the error code was not 62", reporting a check that never ran
        as passed — so this asserts None, not True.
        """
        cert, key = _self_signed(tmp_path, "someone-else.example")
        with TlsServer(cert, key) as srv:
            result = _run(scanner.check_tls("127.0.0.1", srv.port, "localhost"))
        assert result["chain_valid"] is False
        assert result["hostname_match"] is None, (
            "verification never reached the hostname; reporting True would be a "
            "check that did not run being presented as passed"
        )

    def test_the_failure_classifier_only_blames_the_hostname_when_it_can(self):
        """Unit-level, because a genuine hostname mismatch needs a trusted CA
        and the interesting logic is the classification, not the plumbing."""
        assert Scanner._classify_verification_failure(62) is True   # mismatch
        assert Scanner._classify_verification_failure(18) is None   # self-signed
        assert Scanner._classify_verification_failure(10) is None   # expired
        assert Scanner._classify_verification_failure(None) is None


class TestSniIsSent:
    def test_hostname_is_recorded_as_sent(self, scanner, tmp_path):
        cert, key = _self_signed(tmp_path, "localhost")
        with TlsServer(cert, key) as srv:
            result = _run(scanner.check_tls("127.0.0.1", srv.port, "localhost"))
        assert result["sni_sent"] is True

    def test_scanning_a_bare_ip_records_that_no_sni_was_possible(self, scanner, tmp_path):
        """Honest rather than silent: without a hostname there is nothing to
        put in SNI, and the certificate read back is whatever the server
        defaults to — which the report should not present as this host's."""
        cert, key = _self_signed(tmp_path, "localhost")
        with TlsServer(cert, key) as srv:
            result = _run(scanner.check_tls("127.0.0.1", srv.port, None))
        assert result["sni_sent"] is False

    def test_the_implementation_passes_server_hostname(self):
        """Structural guard. The parameter is easy to drop in a refactor and its
        absence is invisible except against a CDN, where it silently reads
        another tenant's certificate."""
        import inspect

        source = inspect.getsource(Scanner.check_tls)
        assert "server_hostname=server_hostname" in source
        assert source.count("server_hostname=") >= 2


class TestObsoleteProtocolProbe:
    def test_the_probe_is_available_on_this_build(self, scanner):
        """If this fails, every weak-TLS result from this image is meaningless —
        which was true of the shipped image until the SECLEVEL=0 probe context.
        The scanner now reports that state instead of implying a clean server."""
        assert Scanner._weak_probe_available() is True

    def test_tls10_only_server_is_detected(self, scanner, tmp_path):
        """The regression that mattered: this returned [] on every host."""
        cert, key = _self_signed(tmp_path, "localhost")
        with TlsServer(cert, key, version=ssl.TLSVersion.TLSv1) as srv:
            result = _run(scanner.check_tls("127.0.0.1", srv.port, "localhost"))
        assert "TLSv1.0" in result["weak_versions"], result

    def test_a_modern_server_reports_no_weak_versions(self, scanner, tmp_path):
        """Control. Without it, a probe that reported TLS 1.0 everywhere would
        also pass the test above."""
        cert, key = _self_signed(tmp_path, "localhost")
        with TlsServer(cert, key, version=ssl.TLSVersion.TLSv1_2) as srv:
            result = _run(scanner.check_tls("127.0.0.1", srv.port, "localhost"))
        assert result["weak_versions"] == [], result

    def test_probe_availability_is_reported(self, scanner, tmp_path):
        cert, key = _self_signed(tmp_path, "localhost")
        with TlsServer(cert, key) as srv:
            result = _run(scanner.check_tls("127.0.0.1", srv.port, "localhost"))
        assert result["weak_probe_supported"] is True


class TestNonTlsPortsAreSkipped:
    def test_port_80_returns_nothing(self, scanner):
        assert _run(scanner.check_tls("127.0.0.1", 80, "localhost")) == {}
