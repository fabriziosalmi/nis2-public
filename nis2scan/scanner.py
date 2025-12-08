import asyncio
import socket
import ssl
import logging
import ipaddress
import aiohttp
import time
import itertools
from typing import List, Dict, Any, Union
from urllib.parse import urlparse
from dataclasses import dataclass, field

import dns.resolver
import dns.zone
import dns.query
import dns.exception

# Phase 5 modules
from .legal import LegalChecker
from .resilience import ResilienceChecker
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
                 return [str(ip) for ip, _ in zip(ip_net.hosts(), range(256))]
            return [str(ip) for ip in ip_net.hosts()]
        except ValueError:
            pass

        # Check if basic IP
        try:
            ipaddress.ip_address(target)
            return [target]
        except ValueError:
            pass
        
        # Assume Domain - resolve to IP (simple resolution)
        try:
            # We use sync gethostbyname for simplicity in resolution phase or aiodns could be used
            # For now, let's just return the domain and resolve during connection or resolve here.
            # A full scanner would do DNS enum. We will just scan the primary A record.
            ip = socket.gethostbyname(target)
            return [ip] 
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
                async with session.get(url, headers={"Host": host_header}) as resp:
                    result['status'] = resp.status
                    result['headers'] = dict(resp.headers)
                    result['redirects'] = [str(r.url) for r in resp.history]
                    # Check security headers
                    result['missing_headers'] = []
                    for h in ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options']:
                        if h not in resp.headers:
                            result['missing_headers'].append(h)
                    
                    # Phase 5: Enhanced checks
                    body = await resp.text()
                    
                    # WAF/CDN Detection
                    cookies_str = "; ".join([f"{k}={v}" for k, v in resp.cookies.items()])
                    result['waf_cdn'] = self.resilience_checker.detect_waf_cdn(
                        dict(resp.headers), cookies_str
                    )
                    
                    # Legal compliance (Italian requirements, cookie banner)
                    # User Requirement: Check P.IVA only on www and root domains, not IPs or service subdomains.
                    should_check_legal = False
                    try:
                        # Check if IP
                        ipaddress.ip_address(host_header)
                    except ValueError:
                        # Not an IP, assume domain
                        parts = host_header.split('.')
                        if host_header.startswith('www.'):
                            should_check_legal = True
                        elif len(parts) == 2:
                            # e.g. example.com
                            should_check_legal = True
                        elif len(parts) == 3 and len(parts[-1]) == 2 and len(parts[-2]) <= 3:
                            # Heuristic for co.uk, com.it, etc.
                            should_check_legal = True
                    
                    if should_check_legal:
                        result['legal'] = self.legal_checker.analyze_page(url, body)
                    
                    # Secrets detection
                    result['secrets'] = self.secrets_detector.scan_content(body, url)
                    
                    # Security.txt Check (RFC 9116)
                    # We check /.well-known/security.txt relative to root
                    try:
                        sec_url = f"{schema}://{ip}:{port}/.well-known/security.txt"
                        async with session.get(sec_url, headers={"Host": host_header}) as sec_resp:
                            if sec_resp.status == 200:
                                result['security_txt_found'] = True
                                result['security_txt_url'] = sec_url
                            else:
                                # Try fallback /security.txt
                                sec_url_alt = f"{schema}://{ip}:{port}/security.txt"
                                async with session.get(sec_url_alt, headers={"Host": host_header}) as sec_resp_alt:
                                    if sec_resp_alt.status == 200:
                                        result['security_txt_found'] = True
                                        result['security_txt_url'] = sec_url_alt
                    except Exception:
                        pass # Ignore errors during security.txt check

                    if self.evidence_collector:
                        self.evidence_collector.save_raw_evidence(ip, f"port_{port}_http_body", body, "html")
                        self.evidence_collector.save_raw_evidence(ip, f"port_{port}_http_headers", str(resp.headers), "txt")
        except Exception as e:
            result['error'] = str(e)
            
        return result

    async def check_tls(self, ip: str, port: int, hostname: str = None) -> Dict[str, Any]:
        if port not in [443, 8443]:
            return {}
        
        result = {'valid': False, 'version': 'unknown', 'expired': False, 'expiry_date': None}
        try:
            # We connect nicely to get the cert
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_OPTIONAL # Allow getting cert even if not verified?
            
            # Note: asyncio doesn't expose getpeercert() easily without verify.
            # We will use a synchronous wrap for the certificate part solely because of stdlib limitations in async ssl
            # or just accept basic info for now.
            # Let's stick to version for this iteration to avoid blocking loop.
            
            conn = asyncio.open_connection(ip, port, ssl=context)
            reader, writer = await asyncio.wait_for(conn, timeout=5.0)
            
            ssl_obj = writer.get_extra_info('ssl_object')
            cert = ssl_obj.getpeercert()
            
            result['version'] = ssl_obj.version()
            result['cipher'] = ssl_obj.cipher()
            # Extract cert details manually or simple verification check
            # For this MVP let's assume if we can handshake, we check if generic verify would fail
            # We can try a second connection with verify_mode=CERT_REQUIRED to see if it fails validation?
            # Or just rely on version for now.
            
            # Better approach for Expiry: Use OpenSSL or just parsing. 
            # Let's keep it simple for now and rely on version checks primarily, 
            # but note that getting expiry requires `getpeercert()` which requires validation or custom parsing.
            # We will switch verify_mode to OPTIONAL to try and get the cert.
            
            writer.close()
            await writer.wait_closed()

        except Exception as e:
            result['error'] = str(e)
            
        return result

    def check_dns_security_sync(self, domain: str) -> Dict[str, Any]:
        """Check for DNSSEC, Zone Transfer, and Email Security (SPF/DMARC)."""
        # This is the synchronous implementation to be run in a thread
        result = {
            'dnssec_enabled': False,
            'zone_transfer_exposed': False,
            'nameservers': [],
            'spf_record': None,
            'dmarc_record': None
        }
        
        # 1. Check DNSSEC (DNSKEY presence)
        try:
            # We assume if DNSKEY exists, it's at least configured. 
            # Full validation is complex, but this is a good first order check.
            answers = dns.resolver.resolve(domain, 'DNSKEY')
            if answers:
                result['dnssec_enabled'] = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
             result['dnssec_enabled'] = False
        except Exception as e:
             logger.debug(f"DNSSEC check failed for {domain}: {e}")

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
                    result['spf_record'] = txt_val
                    break
        except Exception:
            pass

        # 4. Check DMARC (TXT record on _dmarc.domain)
        try:
            dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for r in dmarc_records:
                txt_val = "".join([s.decode('utf-8') if isinstance(s, bytes) else s for s in r.strings])
                if txt_val.startswith('v=DMARC1'):
                    result['dmarc_record'] = txt_val
                    break
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

    # Bridge method for async/sync exec
    def check_dns_security_sync(self, domain: str) -> Dict[str, Any]:
        """Wrapper to call the async-logic method synchronously or rewrite logic synchronously."""
        # Note: check_dns_security below was written as async but used sync dnspython.
        # It's better to just make the logic method sync since dnspython is sync.
        # I'll paste the logic here directly.
        
        result = {
            'dnssec_enabled': False,
            'zone_transfer_exposed': False,
            'nameservers': []
        }
        
        # 1. Check DNSSEC (DNSKEY presence)
        try:
            answers = dns.resolver.resolve(domain, 'DNSKEY')
            if answers:
                result['dnssec_enabled'] = True
        except Exception:
             result['dnssec_enabled'] = False

        # 2. Check Zone Transfer (AXFR)
        try:
            ns_answers = dns.resolver.resolve(domain, 'NS')
            nameservers = [str(r.target) for r in ns_answers]
            result['nameservers'] = nameservers
            
            for ns in nameservers:
                try:
                    ns_ip = socket.gethostbyname(str(ns))
                    z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=2.0))
                    if z:
                        result['zone_transfer_exposed'] = True
                        break 
                except Exception:
                    continue
        except Exception:
            pass

        # 3. SPF
        try:
            spf_answers = dns.resolver.resolve(domain, 'TXT')
            for r in spf_answers:
                txt_val = "".join([s.decode('utf-8') for s in r.strings])
                if "v=spf1" in txt_val:
                    result['spf'] = {'present': True, 'record': txt_val}
                    break
        except Exception:
            pass

        # 4. DMARC
        try:
            dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for r in dmarc_answers:
                txt_val = "".join([s.decode('utf-8') for s in r.strings])
                if "v=DMARC1" in txt_val:
                    result['dmarc'] = {'present': True, 'record': txt_val}
                    break
        except Exception:
            pass

        return result
