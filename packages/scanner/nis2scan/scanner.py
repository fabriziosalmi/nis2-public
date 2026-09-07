# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import asyncio
import socket
import ssl
import logging
import ipaddress
import aiohttp
import itertools
import re
from typing import List, Dict, Any
from dataclasses import dataclass, field

import dns.resolver
import dns.zone
import dns.query
import dns.exception

# Phase 5 modules
from .legal import LegalChecker
from .resilience import ResilienceChecker
from .headers import evaluate_headers, parse_set_cookie
from .secrets import SecretsDetector, WHOISMonitor

# Setup basic logging
logger = logging.getLogger("nis2scan")

@dataclass
class ScanResult:
    target: str
    ip: str
    is_alive: bool = False
    open_ports: List[int] = field(default_factory=list)
    http_info: Dict[str, Any] = field(default_factory=dict)
    tls_info: Dict[str, Any] = field(default_factory=dict)
    dns_info: Dict[str, Any] = field(default_factory=dict)
    os_match: str = "Unknown"
    # Phase 5 additions
    legal_info: Dict[str, Any] = field(default_factory=dict)
    resilience_info: Dict[str, Any] = field(default_factory=dict)
    secrets_found: List[Dict[str, Any]] = field(default_factory=list)
    whois_info: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


def should_run_legal_checks(host_header: str) -> bool:
    """Is this host the public face of a business, for the Italian legal checks?

    The P.IVA / privacy-notice / cookie-banner checks apply to a commercial
    website, not to `mail.` or `api.` subdomains or bare IPs — running Playwright
    against every host would be slow and would report a missing privacy policy on
    an SMTP endpoint.

    Extracted from inside check_http because the only test covering it
    RE-IMPLEMENTED it in the test file rather than importing it, so it exercised
    nothing that shipped. That copy had already drifted from the original.
    """
    try:
        ipaddress.ip_address(host_header)
        return False  # a bare IP is not a commercial website
    except ValueError:
        pass

    if host_header.startswith('www.'):
        return True
    parts = host_header.split('.')
    if len(parts) == 2:
        return True  # example.com
    # Two-level public suffixes: example.co.uk, example.com.it
    if len(parts) == 3 and len(parts[-1]) == 2 and len(parts[-2]) <= 3:
        return True
    return False


class Scanner:
    def __init__(self, config):
        self.config = config
        self.semaphore = asyncio.Semaphore(config.concurrency)
        self.timeout = config.scan_timeout
        # Enhanced ports list:
        # File/Remote: FTP(21), SSH(22), Telnet(23), RDP(3389), SMB(445)
        # Web: 80, 443, 8080, 8443
        # DB: MySQL(3306), Postgres(5432), Redis(6379), Mongo(27017)
        self.ports_to_scan = [21, 22, 23, 80, 443, 8080, 8443, 3389, 445, 53, 3306, 5432, 6379, 27017]
        self.evidence_collector = getattr(config, 'evidence_collector', None)

        # Phase 5 checkers
        self.legal_checker = LegalChecker()
        self.resilience_checker = ResilienceChecker()
        self.secrets_detector = SecretsDetector()
        self.whois_monitor = WHOISMonitor()

    async def resolve_target(self, target: str) -> List[str]:
        """Resolve a target string (Domain, IP, CIDR) to a list of IPs."""
        try:
            # Check if CIDR
            ip_net = ipaddress.ip_network(target, strict=False)
            # Limit huge networks for safety in this demo
            if ip_net.num_addresses > 256 and ip_net.prefixlen < 24:
                logger.warning(f"Network {target} is large, scanning first 256 only.")
                ips = [str(ip) for ip, _ in zip(ip_net.hosts(), range(256))]
            else:
                ips = [str(ip) for ip in ip_net.hosts()]

            # Filter private IPs if not allowed
            if not getattr(self.config, "allow_private_ips", False):
                filtered = []
                for ip_str in ips:
                    ip = ipaddress.ip_address(ip_str)
                    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                        logger.warning(f"SSRF block: skipping private/reserved IP {ip_str} in range {target}")
                    else:
                        filtered.append(ip_str)
                return filtered
            return ips
        except ValueError:
            pass

        # Check if basic IP
        try:
            ipaddress.ip_address(target)
            if not getattr(self.config, "allow_private_ips", False):
                ip = ipaddress.ip_address(target)
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                    logger.warning(f"SSRF block: skipping private/reserved target IP {target}")
                    return []
            return [target]
        except ValueError:
            pass

        # Domain. Prefer the IP the API pinned at validation time —
        # avoids a TOCTOU window where DNS could be rebinded between
        # validation and scan, redirecting us to a private address.
        pinned = getattr(self.config, "pinned_ips", {}) or {}
        if target in pinned:
            pinned_ip = pinned[target]
            if not getattr(self.config, "allow_private_ips", False):
                try:
                    ip = ipaddress.ip_address(pinned_ip)
                    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                        logger.warning(f"SSRF block: skipping private/reserved pinned IP {pinned_ip} for {target}")
                        return []
                except ValueError:
                    logger.warning(f"SSRF block: invalid pinned IP {pinned_ip} for {target}")
                    return []
            logger.debug(f"Using pinned IP {pinned_ip} for {target}")
            return [pinned_ip]

        # Fallback for CLI / no pre-resolution path.
        try:
            ip_str = socket.gethostbyname(target)
            if not getattr(self.config, "allow_private_ips", False):
                ip = ipaddress.ip_address(ip_str)
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                    logger.warning(f"SSRF block: skipping private/reserved resolved IP {ip_str} for {target}")
                    return []
            return [ip_str]
        except socket.gaierror:
            logger.error(f"Could not resolve domain: {target}")
            return []


    async def check_port(self, ip: str, port: int) -> bool:
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=2.0)
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False

    async def check_http(self, ip: str, port: int, hostname: str = None) -> Dict[str, Any]:
        schema = "https" if port in [443, 8443] else "http"
        host_header = hostname if hostname else ip
        url = f"{schema}://{ip}:{port}/"

        result = {}

        try:
            # We want to inspect SSL separately or just ignore errors here to get headers
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                async with session.get(url, headers={"Host": host_header}, allow_redirects=False) as resp:
                    result['status'] = resp.status
                    result['headers'] = dict(resp.headers)
                    # SSRF: do NOT follow redirects — a 3xx Location could point at
                    # an internal host / metadata endpoint that aiohttp would
                    # re-resolve (bypassing the pinned IP). Record where it *would*
                    # have gone for visibility instead of following it.
                    result['redirects'] = []
                    if 'Location' in resp.headers:
                        result['redirect_location'] = resp.headers.get('Location')
                    # Security headers, EVALUATED. The previous version only
                    # recorded which of three names were absent, so
                    # `default-src *; script-src 'unsafe-inline'` and
                    # `max-age=1` both counted as satisfied controls.
                    result['missing_headers'] = []
                    for h in ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options']:
                        if h not in resp.headers:
                            result['missing_headers'].append(h)
                    result['header_issues'] = [
                        {
                            'header': i.header,
                            'severity': i.severity,
                            'summary': i.summary,
                            'detail': i.detail,
                        }
                        for i in evaluate_headers(dict(resp.headers))
                    ]

                    # Phase 5: Enhanced checks
                    # Prevent OOM / memory exhaustion by capping the body read to 1MB.
                    # Malicious or misconfigured servers could serve a 5GB ISO or continuous stream.
                    body_bytes = await resp.content.read(1024 * 1024)
                    try:
                        body = body_bytes.decode('utf-8', errors='ignore')
                    except Exception:
                        body = ""

                    # WAF/CDN Detection
                    cookies_str = "; ".join([f"{k}={v}" for k, v in resp.cookies.items()])
                    result['waf_cdn'] = self.resilience_checker.detect_waf_cdn(
                        dict(resp.headers), cookies_str
                    )

                    # Cookie flags, parsed as ATTRIBUTES. Substring matching on
                    # the raw line counted `secure_session=1` as Secure and made
                    # `SameSite=None` — weaker than omitting the attribute —
                    # indistinguishable from `SameSite=Strict`.
                    result['cookies_analysis'] = []
                    raw_cookies = resp.headers.getall('Set-Cookie', [])
                    for rc in raw_cookies:
                        flags = parse_set_cookie(rc)
                        result['cookies_analysis'].append({
                            'name': flags.name,
                            'secure': flags.secure,
                            'httponly': flags.httponly,
                            'samesite': flags.samesite,
                            'issues': flags.issues,
                        })

                    # Subresource Integrity (SRI) Check
                    result['sri_missing'] = []
                    # Find external scripts
                    # Regex to find <script src="...">
                    script_tags = re.finditer(r'<script[^>]+src=["\'](http[s]?://[^"\']+)["\'][^>]*>', body, re.IGNORECASE)

                    for match in script_tags:
                        src = match.group(1)
                        full_tag = match.group(0)

                        # Check if external (heuristic: doesn't contain our hostname)
                        # We also ignore common local references like localhost or relative paths (already filtered by regex http)
                        if host_header not in src:
                            # It's external
                            # Check for integrity attribute
                            if 'integrity=' not in full_tag:
                                result['sri_missing'].append(src)

                    # Legal compliance (Italian requirements, cookie banner)
                    # User Requirement: Check P.IVA only on www and root domains, not IPs or service subdomains.
                    if should_run_legal_checks(host_header):
                        # Use FQDN for legal checks so Playwright visits the real domain, not the IP
                        legal_url = f"{schema}://{host_header}"
                        if port not in [80, 443]:
                            legal_url += f":{port}"
                        legal_url += "/"
                        # Pass the pinned IP so Playwright resolves the FQDN to the
                        # same validated address (no DNS rebinding at render time).
                        result['legal'] = await self.legal_checker.analyze_page(
                            legal_url, body, pinned_ip=ip
                        )

                    # Secrets detection
                    result['secrets'] = self.secrets_detector.scan_content(body, url)

                    # Security.txt Check (RFC 9116)
                    # We check /.well-known/security.txt relative to root
                    try:
                        sec_url = f"{schema}://{ip}:{port}/.well-known/security.txt"
                        async with session.get(sec_url, headers={"Host": host_header}, allow_redirects=False) as sec_resp:
                            if sec_resp.status == 200:
                                result['security_txt_found'] = True
                                result['security_txt_url'] = sec_url
                            else:
                                # Try fallback /security.txt
                                sec_url_alt = f"{schema}://{ip}:{port}/security.txt"
                                async with session.get(sec_url_alt, headers={"Host": host_header}, allow_redirects=False) as sec_resp_alt:
                                    if sec_resp_alt.status == 200:
                                        result['security_txt_found'] = True
                                        result['security_txt_url'] = sec_url_alt
                    except Exception:
                        pass # Ignore errors during security.txt check

                    # Sensitive File Checks (Cyber Hygiene)
                    result['sensitive_files'] = []
                    for sensitive_path in ['/.git/HEAD', '/.env']:
                        try:
                            sens_url = f"{schema}://{ip}:{port}{sensitive_path}"
                            async with session.get(sens_url, headers={"Host": host_header}, allow_redirects=False) as sens_resp:
                                if sens_resp.status == 200:
                                    # Verify content to avoid false positives (e.g. custom 404 pages returning 200).
                                    # Cap the read at 64KB so a malicious server streaming a huge body to
                                    # /.env or /.git/HEAD cannot OOM the worker — the marker strings we
                                    # look for are tiny and sit at the very start of the file.
                                    raw = await sens_resp.content.read(64 * 1024)
                                    content = raw.decode('utf-8', errors='ignore')
                                    if sensitive_path == '/.git/HEAD' and 'ref: refs/' in content:
                                        result['sensitive_files'].append(sensitive_path)
                                    elif sensitive_path == '/.env' and '=' in content:
                                        result['sensitive_files'].append(sensitive_path)
                        except Exception:
                            pass

                    if self.evidence_collector:
                        self.evidence_collector.save_raw_evidence(ip, f"port_{port}_http_body", body, "html")
                        self.evidence_collector.save_raw_evidence(ip, f"port_{port}_http_headers", str(resp.headers), "txt")
        except Exception as e:
            result['error'] = str(e)

        return result

    # A probe that cannot fail is worse than no probe: it reports "clean".
    #
    # Debian bookworm — the base image this ships on — sets OpenSSL's default
    # security level to 2, which refuses TLS 1.0/1.1 CLIENT-side regardless of
    # `minimum_version`. Verified inside the running container: the handshake
    # dies with NO_CIPHERS_AVAILABLE before a single byte reaches the target, the
    # `except` below swallowed it, and `weak_versions` came back empty for every
    # host on earth — including ones genuinely serving TLS 1.0.
    #
    # `@SECLEVEL=0` on the probe context only. It is scoped to these throwaway
    # contexts and never touches the connection used to read the certificate.
    _WEAK_PROBE_CIPHERS = "ALL:@SECLEVEL=0"

    # Ports probed for TLS. A named constant rather than a literal inside
    # check_tls: as an inline list the limitation was invisible, and TLS served
    # on any other port — 9443, 8080 with implicit TLS, a management interface —
    # was skipped with no trace in the report.
    TLS_PORTS = (443, 8443)

    async def _probe_protocol(self, ip: str, port: int, hostname: str,
                              version: "ssl.TLSVersion") -> bool:
        """True when the server completes a handshake at exactly `version`."""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
            try:
                ctx.set_ciphers(self._WEAK_PROBE_CIPHERS)
            except ssl.SSLError:
                # An OpenSSL build that refuses SECLEVEL=0 cannot probe these
                # protocols at all. Report "not detected" rather than "absent".
                return False
            conn = asyncio.open_connection(
                ip, port, ssl=ctx, server_hostname=hostname or None
            )
            _, writer = await asyncio.wait_for(conn, timeout=5.0)
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    async def check_tls(self, ip: str, port: int, hostname: str = None) -> Dict[str, Any]:
        if port not in self.TLS_PORTS:
            return {}

        result: Dict[str, Any] = {
            'handshake_ok': False,
            'version': 'unknown',
            'chain_valid': None,
            'chain_error': None,
            'hostname_match': None,
            'sni_sent': bool(hostname),
            'weak_versions': [],
            'weak_probe_supported': True,
        }

        # SNI. The previous version called open_connection() with no
        # server_hostname and check_hostname=False, so no SNI was sent at all:
        # against any shared IP, CDN or load balancer the server answered with
        # its DEFAULT certificate and every conclusion drawn was about somebody
        # else's site. The scan pins the resolved IP (DNS-rebinding defence), so
        # the hostname has to travel in the handshake or it travels nowhere.
        server_hostname = hostname or None

        # Two connections on purpose. The first VALIDATES — full chain and
        # hostname verification, which is the only way `chain_valid` can mean
        # anything. The old code set verify_mode=CERT_OPTIONAL with
        # check_hostname=False and then reported the result as `valid`, so
        # "valid" meant "a handshake completed", which is not a security
        # property.
        try:
            strict = ssl.create_default_context()
            conn = asyncio.open_connection(
                ip, port, ssl=strict, server_hostname=server_hostname
            )
            _, writer = await asyncio.wait_for(conn, timeout=5.0)
            result['chain_valid'] = True
            result['hostname_match'] = True
            writer.close()
            await writer.wait_closed()
        except ssl.SSLCertVerificationError as exc:
            result['chain_valid'] = False
            result['chain_error'] = exc.verify_message or str(exc)
            mismatch = self._classify_verification_failure(
                getattr(exc, 'verify_code', None)
            )
            # False only when the hostname is demonstrably the cause; None when
            # an earlier fault stopped verification before the name was checked.
            result['hostname_match'] = False if mismatch else None
        except Exception as exc:
            result['chain_error'] = str(exc)

        # The second connection READS the negotiated parameters, and must not
        # abort on an untrusted chain — a self-signed certificate is a finding to
        # report, not a reason to return nothing about the host.
        try:
            lax = ssl.create_default_context()
            lax.check_hostname = False
            lax.verify_mode = ssl.CERT_NONE
            conn = asyncio.open_connection(
                ip, port, ssl=lax, server_hostname=server_hostname
            )
            _, writer = await asyncio.wait_for(conn, timeout=5.0)
            ssl_obj = writer.get_extra_info('ssl_object')
            if ssl_obj is not None:
                result['version'] = ssl_obj.version()
                cipher_info = ssl_obj.cipher()
                if cipher_info:
                    result['cipher'] = cipher_info[0]
                    result['cipher_bits'] = cipher_info[2]
            result['handshake_ok'] = True
            writer.close()
            await writer.wait_closed()
        except Exception as exc:
            # Do NOT return here. A server that speaks only TLS 1.0 refuses this
            # modern context, and that is precisely the host whose obsolete
            # protocols most need reporting — bailing out would have made the
            # worst case the one the scanner stays silent about.
            result['error'] = str(exc)

        # Active downgrade probe, one connection per obsolete protocol.
        for label, version in (
            ('TLSv1.0', ssl.TLSVersion.TLSv1),
            ('TLSv1.1', ssl.TLSVersion.TLSv1_1),
        ):
            if await self._probe_protocol(ip, port, server_hostname, version):
                result['weak_versions'].append(label)

        # Whether this build could have detected them at all. Without it a
        # missing finding is indistinguishable from a clean server, which is the
        # exact ambiguity that hid the bookworm defect.
        result['weak_probe_supported'] = self._weak_probe_available()
        return result

    # OpenSSL verify code for "hostname mismatch". Everything else that reaches
    # SSLCertVerificationError is a chain fault.
    _VERIFY_HOSTNAME_MISMATCH = 62

    @classmethod
    def _classify_verification_failure(cls, verify_code) -> "bool | None":
        """Was the hostname the reason verification failed?

        Returns True for a hostname mismatch, None when it could not be
        determined. `None` is the important case and the previous code got it
        wrong: OpenSSL stops at the first fault, so a self-signed certificate
        fails as self-signed and the hostname is never examined. Inferring
        "hostname is fine" from "the error was not 62" reported a check that
        never ran as passed — the shape of false assurance this scanner is being
        cleaned of.
        """
        if verify_code is None:
            return None
        return True if verify_code == cls._VERIFY_HOSTNAME_MISMATCH else None

    @staticmethod
    def _weak_probe_available() -> bool:
        """Can this OpenSSL build negotiate TLS 1.0 as a client at all?"""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1
            ctx.set_ciphers(Scanner._WEAK_PROBE_CIPHERS)
            return len(ctx.get_ciphers()) > 0
        except Exception:
            return False

    def check_dns_security_sync(self, domain: str) -> Dict[str, Any]:
        """Check for DNSSEC, Zone Transfer, Email Security (SPF/DMARC), and Redundancy (MX)."""
        # This is the synchronous implementation to be run in a thread
        result = {
            'dnssec_enabled': False,
            'dnssec_dnskey': False,
            'dnssec_ds': False,
            'zone_transfer_exposed': False,
            'nameservers': [],
            'spf': {'present': False, 'record': None},
            'dmarc': {'present': False, 'record': None},
            'mx': []
        }

        # 1. DNSSEC. A DNSKEY in the zone is NOT DNSSEC: without a DS record in
        #    the parent zone there is no chain of trust, resolvers ignore the
        #    signatures entirely, and the zone is unprotected. Signed-but-
        #    undelegated is the most common DNSSEC misconfiguration there is, and
        #    inferring "enabled" from a DNSKEY reported exactly that case as
        #    compliant — under Art. 21(2)(h), on a control an auditor may check.
        result['dnssec_dnskey'] = False
        result['dnssec_ds'] = False
        try:
            if dns.resolver.resolve(domain, 'DNSKEY'):
                result['dnssec_dnskey'] = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass
        except Exception as e:
            logger.debug(f"DNSKEY lookup failed for {domain}: {e}")

        try:
            # The DS lives in the PARENT zone, which is why it is the delegation
            # signal: only the parent can publish it.
            if dns.resolver.resolve(domain, 'DS'):
                result['dnssec_ds'] = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass
        except Exception as e:
            logger.debug(f"DS lookup failed for {domain}: {e}")

        # Both halves, or the chain does not reach this zone.
        result['dnssec_enabled'] = result['dnssec_dnskey'] and result['dnssec_ds']

        # 2. Check Zone Transfer (AXFR)
        try:
            ns_answers = dns.resolver.resolve(domain, 'NS')
            nameservers = [str(r.target) for r in ns_answers]
            result['nameservers'] = nameservers

            for ns in nameservers:
                try:
                    # Resolve NS to IP
                    ns_ip = socket.gethostbyname(str(ns))
                    # Attempt AXFR
                    z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
                    if z:
                        result['zone_transfer_exposed'] = True
                        break # Found one, that's enough
                except Exception:
                    continue
        except Exception as e:
            logger.debug(f"AXFR check failed for {domain}: {e}")

        # 3. Check SPF (TXT record on domain)
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            for r in txt_records:
                # r.to_text() returns quoted string like '"v=spf1 ..."'
                # We need to handle potential multi-string records
                txt_val = "".join([s.decode('utf-8') if isinstance(s, bytes) else s for s in r.strings])
                if txt_val.startswith('v=spf1'):
                    result['spf'] = {'present': True, 'record': txt_val}
                    break
        except Exception:
            pass

        # 4. Check DMARC (TXT record on _dmarc.domain)
        try:
            dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for r in dmarc_records:
                txt_val = "".join([s.decode('utf-8') if isinstance(s, bytes) else s for s in r.strings])
                if txt_val.startswith('v=DMARC1'):
                    result['dmarc'] = {'present': True, 'record': txt_val}
                    break
        except Exception:
            pass

        # 5. Check MX Records (Redundancy)
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            result['mx'] = [str(r.exchange) for r in mx_records]
        except Exception:
            pass

        return result

    async def check_dns_security(self, domain: str) -> Dict[str, Any]:
        # Wrapper for backward compatibility if needed, but we use check_dns_security_sync
        return self.check_dns_security_sync(domain)

    async def get_targets(self) -> List[tuple]:
        target_groups = []

        # 1. Expand all targets first, keeping them grouped
        # Support IP Ranges
        for t in self.config.targets.ip_ranges:
             ips = await self.resolve_target(t)
             if ips:
                target_groups.append([(ip, t) for ip in ips])

        for t in self.config.targets.domains:
             ips = await self.resolve_target(t)
             if ips:
                target_groups.append([(ip, t) for ip in ips])

        # 2. Apply Limits with Round-Robin Balancing
        if self.config.max_hosts > 0:
            # Interleave targets from all groups to ensure fair coverage
            # zip_longest((A1, A2), (B1,)) -> (A1, B1), (A2, None)
            interleaved = [x for x in itertools.chain.from_iterable(itertools.zip_longest(*target_groups)) if x is not None]

            logger.info(f"Limiting scan to {self.config.max_hosts} hosts (balanced across {len(target_groups)} ranges/domains).")
            return interleaved[:self.config.max_hosts]

        # Flatten if no limit
        all_targets = [item for group in target_groups for item in group]
        return all_targets

    async def scan_targets(self, targets: List[tuple]):
        tasks = []

        # 3. Create Tasks
        if self.config.dry_run:
            logger.info("DRY RUN: Skipping actual network scan.")
            for ip, original_target in targets:
                 # Return a mock "INFO" result
                 res = ScanResult(target=original_target, ip=ip, is_alive=False)
                 res.errors.append("Dry Run: Skipped")
                 tasks.append(asyncio.create_task(self._mock_return(res)))
        else:
            for ip, original_target in targets:
                 tasks.append(self.scan_ip(ip, original_target))

        # Iteratively yield results as they finish
        for task in asyncio.as_completed(tasks):
            yield await task

    async def run(self) -> List[ScanResult]:
        # Legacy/Simple wrapper
        targets = await self.get_targets()
        results = []
        async for res in self.scan_targets(targets):
            results.append(res)
        return results

    async def _mock_return(self, res):
        return res

    async def scan_ip(self, ip: str, original_target: str) -> ScanResult:
        async with self.semaphore:
            res = ScanResult(target=original_target, ip=ip)

            # DNS Audit (if target is a domain) and Enabled
            # Robust check: Try to parse as IP/Network, if fail -> Domain
            is_domain = False
            try:
                ipaddress.ip_address(original_target)
            except ValueError:
                try:
                    ipaddress.ip_network(original_target)
                except ValueError:
                    is_domain = True

            if is_domain and self.config.features.get('dns_checks', True):
                # To avoid blocking asyncio loop with dnspython (which is sync by default usually),
                # we SHOULD run it in executor, but for this MVP, quick sync call is okay-ish
                # or we use to_thread.
                try:
                    res.dns_info = await asyncio.to_thread(self.check_dns_security_sync, original_target)
                except AttributeError:
                    # Python < 3.9 fallback
                    res.dns_info = self.check_dns_security_sync(original_target)

            # Phase 5: WHOIS domain expiry check
            if is_domain and self.config.features.get('whois_checks', True):
                try:
                    res.whois_info = await asyncio.to_thread(
                        self.whois_monitor.check_domain_expiry, original_target
                    )
                except AttributeError:
                    res.whois_info = self.whois_monitor.check_domain_expiry(original_target)
                except Exception as e:
                    logger.debug(f"WHOIS check failed for {original_target}: {e}")

            # Scan ports (if enabled)
            if self.config.features.get('port_scan', True):
                for port in self.ports_to_scan:
                    is_open = await self.check_port(ip, port)
                    if is_open:
                        res.open_ports.append(port)

            # Deep check web ports (if web_checks enabled)
            if self.config.features.get('web_checks', True):
                ports_to_remove = []
                for p in res.open_ports:
                    if p in [80, 443, 8080, 8443]:
                        # Determine hostname to use
                        # If original_target is a CIDR or IP, use the IP as Host header (or reverse DNS if we had it)
                        # If original_target is a domain, use it.
                        if '/' in original_target or original_target == ip:
                            h_name = ip
                        else:
                            h_name = original_target

                        http_data = await self.check_http(ip, p, hostname=h_name)
                        res.http_info[p] = http_data

                        # OS Fingerprinting from Server Header
                        if 'headers' in http_data:
                            if 'Server' in http_data['headers']:
                                res.os_match = http_data['headers']['Server']

                            # Capture Tech Stack (X-Powered-By, etc)
                            tech_stack = []
                            if 'X-Powered-By' in http_data['headers']:
                                tech_stack.append(f"Powered-By: {http_data['headers']['X-Powered-By']}")
                            if 'X-AspNet-Version' in http_data['headers']:
                                tech_stack.append(f"AspNet: {http_data['headers']['X-AspNet-Version']}")
                            if 'X-Generator' in http_data['headers']:
                                tech_stack.append(f"Generator: {http_data['headers']['X-Generator']}")

                            if tech_stack:
                                http_data['tech_stack'] = tech_stack

                        # If HTTP check failed (connection error), treat port as closed
                        # This filters out false positives from transparent proxies/firewalls
                        if 'error' in http_data:
                            ports_to_remove.append(p)
                        elif p in [443, 8443]:
                            tls_data = await self.check_tls(ip, p, hostname=h_name)
                            res.tls_info[p] = tls_data

                for p in ports_to_remove:
                    res.open_ports.remove(p)

            # Simple OS Fingerprinting based on ports if still unknown
            if res.os_match == "Unknown":
                if 445 in res.open_ports or 139 in res.open_ports:
                    res.os_match = "Windows (Likely)"
                elif 22 in res.open_ports:
                    res.os_match = "Linux/Unix (Likely)"

            if not res.open_ports:
                res.is_alive = False
            else:
                res.is_alive = True

            return res
