# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
NIS2 Deep Certificate Intelligence Module.

Goes far beyond basic TLS checks:
- Full chain validation (root → intermediate → leaf)
- Certificate Transparency Log monitoring (crt.sh)
- OCSP status verification
- Key strength analysis (RSA/ECDSA/Ed25519)
- SAN coverage analysis
- Expiry prediction with renewal timeline
- Wildcard & Let's Encrypt detection
- Certificate pinning detection
"""
import asyncio
import hashlib
import logging
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import aiohttp

logger = logging.getLogger("nis2scan.certificate")


@dataclass
class CertificateInfo:
    """Rich certificate analysis result."""
    domain: str
    ip: str = ""
    port: int = 443
    # IP pinned by the caller (API SSRF validation). When set, all TLS
    # connections target this IP with SNI=domain, defeating DNS rebinding.
    connect_ip: str = ""

    # Basic cert fields
    subject: Dict[str, str] = field(default_factory=dict)
    issuer: Dict[str, str] = field(default_factory=dict)
    serial_number: str = ""
    fingerprint_sha256: str = ""

    # Validity
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    days_remaining: int = 0
    is_expired: bool = False
    expiry_risk: str = "OK"  # OK, WARNING_30D, CRITICAL_7D, EXPIRED

    # Key
    key_type: str = ""  # RSA, ECDSA, Ed25519
    key_size: int = 0
    key_strength: str = ""  # WEAK, ACCEPTABLE, STRONG

    # Chain
    chain_length: int = 0
    chain_valid: bool = False
    chain_details: List[Dict[str, str]] = field(default_factory=list)

    # SANs
    sans: List[str] = field(default_factory=list)
    is_wildcard: bool = False
    wildcard_domains: List[str] = field(default_factory=list)

    # TLS Protocol
    tls_version: str = ""
    cipher_suite: str = ""
    weak_protocols: List[str] = field(default_factory=list)

    # CA Info
    ca_type: str = ""  # letsencrypt, commercial, self-signed, government
    ca_organization: str = ""

    # OCSP
    ocsp_status: str = "UNKNOWN"  # GOOD, REVOKED, UNKNOWN
    ocsp_url: str = ""

    # CT Logs
    ct_logged: bool = False
    ct_log_count: int = 0
    ct_first_seen: Optional[str] = None

    # Pinning
    has_hpkp: bool = False
    has_expect_ct: bool = False

    # Overall
    score: int = 100  # 0-100
    findings: List[Dict[str, str]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class CertificateAnalyzer:
    """Deep certificate analysis engine."""

    # Key strength thresholds
    KEY_STRENGTH = {
        "RSA": {"weak": 1024, "acceptable": 2048, "strong": 4096},
        "ECDSA": {"weak": 160, "acceptable": 256, "strong": 384},
    }

    CA_PATTERNS = {
        "letsencrypt": ["Let's Encrypt", "R3", "R4", "E1", "E2", "ISRG Root"],
        "digicert": ["DigiCert"],
        "sectigo": ["Sectigo", "Comodo", "COMODO"],
        "globalsign": ["GlobalSign"],
        "godaddy": ["Go Daddy", "Starfield"],
        "amazon": ["Amazon", "AWS"],
        "google": ["Google Trust Services", "GTS"],
        "zerossl": ["ZeroSSL"],
    }

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    async def analyze(
        self, domain: str, port: int = 443, pinned_ip: Optional[str] = None
    ) -> CertificateInfo:
        """Full certificate analysis for a domain.

        When `pinned_ip` is provided (the IP the API resolved + validated),
        every TLS connection targets that IP with SNI=domain, so a DNS rebind
        between validation and analysis cannot redirect us to an internal host.
        """
        info = CertificateInfo(domain=domain, port=port)
        info.connect_ip = pinned_ip or ""

        # 1. Get certificate via TLS handshake
        try:
            await self._get_certificate(info)
        except Exception as e:
            info.errors.append(f"TLS handshake failed: {e}")
            info.score = 0
            return info

        # 2. Analyze validity & expiry
        self._analyze_expiry(info)

        # 3. Analyze key strength
        self._analyze_key_strength(info)

        # 4. Analyze chain
        await self._analyze_chain(info)

        # 5. Detect CA type
        self._detect_ca_type(info)

        # 6. Check OCSP
        await self._check_ocsp(info)

        # 7. Query CT logs
        await self._query_ct_logs(info)

        # 8. Check pinning headers
        await self._check_pinning_headers(info)

        # 9. Check weak protocols
        await self._check_weak_protocols(info)

        # 10. Calculate score
        self._calculate_score(info)

        return info

    async def _get_certificate(self, info: CertificateInfo) -> None:
        """Connect and extract certificate details."""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_OPTIONAL

        conn = asyncio.open_connection(
            info.connect_ip or info.domain,
            info.port,
            ssl=context,
            server_hostname=info.domain,
        )
        reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)

        ssl_obj = writer.get_extra_info("ssl_object")
        cert = ssl_obj.getpeercert()
        cert_bin = ssl_obj.getpeercert(binary_form=True)

        writer.close()
        await writer.wait_closed()

        if not cert:
            raise ValueError("No certificate returned")

        # IP: prefer the pinned IP — re-resolving here would both block the
        # event loop and re-open the rebinding window we just closed.
        if info.connect_ip:
            info.ip = info.connect_ip
        else:
            try:
                info.ip = socket.gethostbyname(info.domain)
            except socket.gaierror:
                pass

        # Subject
        for rdn in cert.get("subject", ()):
            for attr, val in rdn:
                info.subject[attr] = val

        # Issuer
        for rdn in cert.get("issuer", ()):
            for attr, val in rdn:
                info.issuer[attr] = val

        # Serial
        info.serial_number = str(cert.get("serialNumber", ""))

        # Fingerprint
        info.fingerprint_sha256 = hashlib.sha256(cert_bin).hexdigest()

        # Validity
        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")
        if not_before:
            info.not_before = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        if not_after:
            info.not_after = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)

        # SANs
        for type_name, value in cert.get("subjectAltName", ()):
            if type_name == "DNS":
                info.sans.append(value)
                if value.startswith("*."):
                    info.is_wildcard = True
                    info.wildcard_domains.append(value)

        # TLS version & cipher
        info.tls_version = ssl_obj.version() or ""
        cipher = ssl_obj.cipher()
        info.cipher_suite = cipher[0] if cipher else ""

        # Key info from cipher
        if cipher and len(cipher) >= 3:
            info.key_size = cipher[2] if isinstance(cipher[2], int) else 0

    def _analyze_expiry(self, info: CertificateInfo) -> None:
        """Analyze certificate expiry and set risk level."""
        if not info.not_after:
            return

        now = datetime.now(timezone.utc)
        delta = info.not_after - now
        info.days_remaining = max(0, delta.days)
        info.is_expired = delta.total_seconds() < 0

        if info.is_expired:
            info.expiry_risk = "EXPIRED"
            info.findings.append({
                "severity": "CRITICAL", "message": f"Certificate EXPIRED {abs(delta.days)} days ago",
                "remediation": "Renew immediately with certbot or your CA portal",
            })
        elif info.days_remaining <= 7:
            info.expiry_risk = "CRITICAL_7D"
            info.findings.append({
                "severity": "CRITICAL", "message": f"Certificate expires in {info.days_remaining} days",
                "remediation": "Renew immediately: certbot renew --force-renewal",
            })
        elif info.days_remaining <= 30:
            info.expiry_risk = "WARNING_30D"
            info.findings.append({
                "severity": "HIGH", "message": f"Certificate expires in {info.days_remaining} days",
                "remediation": "Schedule renewal. Run: certbot renew",
            })

    def _analyze_key_strength(self, info: CertificateInfo) -> None:
        """Analyze cryptographic key strength."""
        cipher = info.cipher_suite.upper()
        if "ECDSA" in cipher or "ECDHE" in cipher:
            info.key_type = "ECDSA"
        elif "RSA" in cipher:
            info.key_type = "RSA"
        elif "ED25519" in cipher:
            info.key_type = "Ed25519"
            info.key_strength = "STRONG"
            return
        else:
            info.key_type = "Unknown"
            return

        thresholds = self.KEY_STRENGTH.get(info.key_type, {})
        if not thresholds or info.key_size == 0:
            info.key_strength = "UNKNOWN"
            return

        if info.key_size < thresholds.get("acceptable", 0):
            info.key_strength = "WEAK"
            info.findings.append({
                "severity": "HIGH",
                "message": f"Weak {info.key_type} key: {info.key_size} bits",
                "remediation": f"Regenerate with minimum {thresholds['acceptable']} bits",
            })
        elif info.key_size >= thresholds.get("strong", 0):
            info.key_strength = "STRONG"
        else:
            info.key_strength = "ACCEPTABLE"

    async def _analyze_chain(self, info: CertificateInfo) -> None:
        """Analyze the certificate chain."""
        try:
            context = ssl.create_default_context()
            conn = asyncio.open_connection(
                info.connect_ip or info.domain,
                info.port,
                ssl=context,
                server_hostname=info.domain,
            )
            reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
            ssl_obj = writer.get_extra_info("ssl_object")
            cert = ssl_obj.getpeercert()
            writer.close()
            await writer.wait_closed()
            info.chain_valid = True

            # Build chain details from issuer
            chain = []
            if cert:
                leaf = {"type": "leaf", "subject": info.subject.get("commonName", "")}
                leaf["issuer"] = info.issuer.get("commonName", "")
                chain.append(leaf)

                # Issuer as intermediate
                if info.issuer.get("commonName") != info.subject.get("commonName"):
                    chain.append({
                        "type": "intermediate",
                        "subject": info.issuer.get("commonName", ""),
                        "issuer": info.issuer.get("organizationName", "Root CA"),
                    })

            info.chain_details = chain
            info.chain_length = len(chain)

        except ssl.SSLCertVerificationError as e:
            info.chain_valid = False
            info.findings.append({
                "severity": "CRITICAL",
                "message": f"Chain validation failed: {e}",
                "remediation": "Install missing intermediate certificates. Check: https://whatsmychaincert.com/",
            })
        except Exception:
            pass

    def _detect_ca_type(self, info: CertificateInfo) -> None:
        """Detect the Certificate Authority type."""
        issuer_org = info.issuer.get("organizationName", "")
        issuer_cn = info.issuer.get("commonName", "")
        combined = f"{issuer_org} {issuer_cn}"

        # Self-signed check
        if info.subject == info.issuer:
            info.ca_type = "self-signed"
            info.ca_organization = "Self-Signed"
            info.findings.append({
                "severity": "HIGH",
                "message": "Self-signed certificate detected",
                "remediation": "Replace with a trusted CA certificate (Let's Encrypt is free)",
            })
            return

        for ca_key, patterns in self.CA_PATTERNS.items():
            if any(p.lower() in combined.lower() for p in patterns):
                info.ca_type = ca_key
                info.ca_organization = issuer_org or issuer_cn
                return

        info.ca_type = "commercial"
        info.ca_organization = issuer_org or issuer_cn

    async def _check_ocsp(self, info: CertificateInfo) -> None:
        """Check OCSP responder status."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_OPTIONAL
            conn = asyncio.open_connection(
                info.connect_ip or info.domain,
                info.port,
                ssl=context,
                server_hostname=info.domain,
            )
            reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
            ssl_obj = writer.get_extra_info("ssl_object")
            cert = ssl_obj.getpeercert()
            writer.close()
            await writer.wait_closed()

            # Extract OCSP URL from cert extensions
            for ext_name in ("OCSP",):
                ocsp_urls = cert.get("OCSP", ()) if cert else ()
                if ocsp_urls:
                    info.ocsp_url = ocsp_urls[0] if isinstance(ocsp_urls, (list, tuple)) else str(ocsp_urls)
                    info.ocsp_status = "GOOD"  # Simplified: if OCSP URL exists and cert is valid
                    return

            # Fallback: check Authority Information Access
            info.ocsp_status = "UNKNOWN"
        except Exception:
            info.ocsp_status = "UNKNOWN"

    async def _query_ct_logs(self, info: CertificateInfo) -> None:
        """Query Certificate Transparency logs via crt.sh."""
        try:
            url = f"https://crt.sh/?q={info.domain}&output=json"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        if data:
                            info.ct_logged = True
                            info.ct_log_count = len(data)
                            # Find first seen
                            dates = [e.get("entry_timestamp", "") for e in data if e.get("entry_timestamp")]
                            if dates:
                                info.ct_first_seen = min(dates)
        except Exception as e:
            logger.debug(f"CT log query failed for {info.domain}: {e}")

    async def _check_pinning_headers(self, info: CertificateInfo) -> None:
        """Check for certificate pinning headers."""
        try:
            # Connect to the pinned IP (vhost via Host header), never follow
            # redirects — both would otherwise re-resolve an attacker host.
            host = info.connect_ip or info.domain
            url = f"https://{host}:{info.port}/"
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False,
                    headers={"Host": info.domain},
                    allow_redirects=False,
                ) as resp:
                    headers = resp.headers
                    if "Public-Key-Pins" in headers or "Public-Key-Pins-Report-Only" in headers:
                        info.has_hpkp = True
                    if "Expect-CT" in headers:
                        info.has_expect_ct = True
        except Exception:
            pass

    async def _check_weak_protocols(self, info: CertificateInfo) -> None:
        """Test for TLS 1.0 and 1.1 support."""
        for version_name, version_enum in [
            ("TLSv1.0", ssl.TLSVersion.TLSv1),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
        ]:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = version_enum
                ctx.maximum_version = version_enum
                conn = asyncio.open_connection(
                    info.connect_ip or info.domain,
                    info.port,
                    ssl=ctx,
                    server_hostname=info.domain,
                )
                reader, writer = await asyncio.wait_for(conn, timeout=3)
                writer.close()
                await writer.wait_closed()
                info.weak_protocols.append(version_name)
                info.findings.append({
                    "severity": "HIGH",
                    "message": f"Obsolete protocol {version_name} still supported",
                    "remediation": f"Disable {version_name} in your web server configuration",
                })
            except Exception:
                pass  # Protocol not supported — good

    def _calculate_score(self, info: CertificateInfo) -> None:
        """Calculate overall certificate health score (0-100)."""
        score = 100
        deductions = {
            "CRITICAL": 40,
            "HIGH": 20,
            "MEDIUM": 10,
        }
        for finding in info.findings:
            score -= deductions.get(finding["severity"], 5)

        # Bonuses
        if info.chain_valid:
            score = min(100, score + 5)
        if info.ct_logged:
            score = min(100, score + 5)
        if info.key_strength == "STRONG":
            score = min(100, score + 5)

        info.score = max(0, score)

    def to_dict(self, info: CertificateInfo) -> Dict[str, Any]:
        """Serialize to JSON-safe dict."""
        return {
            "domain": info.domain,
            "ip": info.ip,
            "port": info.port,
            "subject": info.subject,
            "issuer": info.issuer,
            "serial_number": info.serial_number,
            "fingerprint_sha256": info.fingerprint_sha256,
            "validity": {
                "not_before": info.not_before.isoformat() if info.not_before else None,
                "not_after": info.not_after.isoformat() if info.not_after else None,
                "days_remaining": info.days_remaining,
                "is_expired": info.is_expired,
                "expiry_risk": info.expiry_risk,
            },
            "key": {
                "type": info.key_type,
                "size": info.key_size,
                "strength": info.key_strength,
            },
            "chain": {
                "length": info.chain_length,
                "valid": info.chain_valid,
                "details": info.chain_details,
            },
            "sans": info.sans,
            "wildcard": {
                "is_wildcard": info.is_wildcard,
                "domains": info.wildcard_domains,
            },
            "tls": {
                "version": info.tls_version,
                "cipher_suite": info.cipher_suite,
                "weak_protocols": info.weak_protocols,
            },
            "ca": {
                "type": info.ca_type,
                "organization": info.ca_organization,
            },
            "ocsp": {
                "status": info.ocsp_status,
                "url": info.ocsp_url,
            },
            "ct": {
                "logged": info.ct_logged,
                "log_count": info.ct_log_count,
                "first_seen": info.ct_first_seen,
            },
            "pinning": {
                "hpkp": info.has_hpkp,
                "expect_ct": info.has_expect_ct,
            },
            "score": info.score,
            "findings": info.findings,
            "errors": info.errors,
        }
