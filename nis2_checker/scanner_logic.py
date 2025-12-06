import requests
import ssl
import socket
import datetime
import os
from urllib.parse import urlparse
import urllib3
from typing import List, Dict, Any

from nis2_checker.nmap_scanner import NmapScanner
from nis2_checker.dns_scanner import DNSScanner
from nis2_checker.whois_scanner import WhoisScanner
from nis2_checker.content_scanner import ContentScanner
from nis2_checker.evidence import EvidenceCollector
from nis2_checker.models import CheckResult, TargetScanResult, Severity
from nis2_checker.audit_mapping import AUDIT_MAPPING
from nis2_checker.logger import setup_logger

# Disable warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = setup_logger("scanner_logic")

class ScannerLogic:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.timeout = config.get('timeout', 10)
        
        # Initialize Scanners
        self.nmap_scanner = NmapScanner(config.get('nmap', {}))
        self.dns_scanner = DNSScanner(config.get('dns', {}))
        self.whois_scanner = WhoisScanner(config.get('whois', {}))
        self.content_scanner = ContentScanner(config.get('content', {}))
        self.evidence_collector = EvidenceCollector()
        
        logger.info("ScannerLogic initialized with all modules")

    def _map_result(self, check_id: str, status: str, details: str, raw_data: Dict[str, Any] = None, severity_override=None) -> CheckResult:
        """Helper to create a CheckResult with NIS2 context."""
        mapping = AUDIT_MAPPING.get(check_id, {
            "name": check_id,
            "article": "Unknown",
            "severity_fail": Severity.LOW,
            "remediation": "Investigate manually."
        })

        severity = Severity.INFO
        if status == "FAIL":
            severity = mapping["severity_fail"]
            if severity_override:
                severity = severity_override
        elif status == "PASS":
            severity = Severity.INFO 

        return CheckResult(
            check_id=check_id,
            name=mapping["name"],
            status=status,
            details=details,
            severity=severity,
            nis2_article=mapping["article"],
            remediation=mapping["remediation"] if status == "FAIL" else None,
            raw_data=raw_data
        )

    def scan_target(self, target: Dict[str, Any]) -> List[TargetScanResult]:
        """Run all enabled checks for a single target or CIDR and return structured results."""
        results = []
        
        # Check for CIDR
        ip = target.get('ip')
        if ip and '/' in ip:
            live_hosts = self.nmap_scanner.discover_hosts(ip)
            for host in live_hosts:
                sub_target = target.copy()
                sub_target['ip'] = host
                sub_target['name'] = f"{target.get('name', 'Network')} - {host}"
                results.extend(self.scan_target(sub_target))
            return results

        # Single Target Scan
        url = target.get('url')
        name = target.get('name', url or ip)
        
        logger.info(f"Starting scan for target: {name} ({url or ip})")
        
        scan_result = TargetScanResult(target=url or ip, name=name)
        
        # Determine target host for socket connections
        host = None
        port = 443
        if url:
            parsed = urlparse(url)
            host = parsed.hostname
            if parsed.port:
                port = parsed.port
        elif ip:
            host = ip

        target_type = target.get('type', 'generic')

        # 1. WHOIS Scan (Domain Expiry)
        if host and self.config.get('checks', {}).get('whois_check', True):
            # Check if host is a domain (not IP) roughly
            if not host.replace('.', '').isdigit():
                whois_res = self.whois_scanner.check_domain_expiry(host)
                scan_result.results.append(self._map_result("domain_expiry", whois_res['status'], whois_res['details'], whois_res.get('data')))

        # 2. Connectivity & Content Checks
        response_body = None
        response_headers = {}
        
        if self.config['checks'].get('connectivity'):
            res, response_obj = self.check_connectivity(url, ip, target)
            scan_result.results.append(self._map_result("connectivity", res['status'], res['details']))
            
            if response_obj:
                response_body = response_obj.text
                response_headers = response_obj.headers

        # 3. Content Analysis (Secrets, Tech Stack)
        if response_body:
            content_res = self.content_scanner.scan_content(response_headers, response_body)
            
            if 'secrets_leak' in content_res:
                s_res = content_res['secrets_leak']
                # Determine Severity Dynamically
                sev = Severity.CRITICAL if s_res['status'] == 'FAIL' else Severity.INFO
                scan_result.results.append(self._map_result("secrets_leak", s_res['status'], s_res['details'], severity_override=sev))
                
            if 'tech_stack' in content_res:
                t_res = content_res['tech_stack']
                sev = Severity.HIGH if t_res['status'] == 'FAIL' else Severity.INFO
                scan_result.results.append(self._map_result("tech_stack", t_res['status'], t_res['details'], severity_override=sev))

        # 4. Web Checks
        if target_type in ['web', 'https', 'generic']:
            if self.config['checks'].get('ssl_tls') and host:
                res = self.check_ssl(host, port)
                scan_result.results.append(self._map_result("ssl_tls", res['status'], res['details'], res.get('data')))

            if self.config['checks'].get('security_headers') and url:
                # We can reuse headers if we already fetched them, but separate check fn is cleaner for now
                if response_headers:
                     res = self.check_headers_from_obj(response_headers)
                else:
                     res = self.check_headers(url, target)
                scan_result.results.append(self._map_result("security_headers", res['status'], res['details']))

        # 5. Nmap Infrastructure Checks
        nmap_raw = self.nmap_scanner.scan_target(target)
        if nmap_raw:
            for check_key, check_val in nmap_raw.items():
                internal_id = check_key
                if check_key == 'ssh_auth': internal_id = 'ssh_password_auth'
                elif check_key == 'tls_versions': internal_id = 'deprecated_tls'
                elif check_key == 'open_mgmt': internal_id = 'open_mgmt_ports'
                elif check_key == 'rdp_security': internal_id = 'rdp_encryption'
                elif check_key == 'smb_security': internal_id = 'smb_signing'
                
                scan_result.results.append(self._map_result(internal_id, check_val['status'], check_val['details']))

        # 6. DNS Checks
        if self.config.get('checks', {}).get('dns_checks', False):
             target_val = target.get('url') or target.get('ip')
             if target_val:
                 dns_raw = self.dns_scanner.scan_target(target_val)
                 for k, v in dns_raw.items():
                     internal_id = k
                     if k == 'spf': internal_id = 'spf_record'
                     elif k == 'dmarc': internal_id = 'dmarc_record'
                     
                     scan_result.results.append(self._map_result(internal_id, v['status'], v['details']))

        # 7. Evidence (Screenshot)
        if self.config.get('checks', {}).get('evidence', True) and url:
             screenshot_path = self.evidence_collector.take_screenshot(url, name)
             # We don't necessarily add a "CheckResult" for this, but maybe we attach it to the TargetScanResult?
             # For now, let's just log it or add a PASS check that it was taken.
             if screenshot_path:
                  scan_result.results.append(self._map_result("evidence_collected", "PASS", f"Screenshot saved to {screenshot_path}"))

        scan_result.calculate_score()
        results.append(scan_result)
        return results

    def _get_auth(self, target):
        """Retrieve authentication credentials from env vars."""
        auth_id = target.get('auth_id')
        if not auth_id:
            return None, None
        token = os.environ.get(f"{auth_id}_TOKEN")
        if token:
            return None, {"Authorization": f"Bearer {token}"}
        user = os.environ.get(f"{auth_id}_USER")
        password = os.environ.get(f"{auth_id}_PASS")
        if user and password:
            return (user, password), None
        return None, None

    def check_connectivity(self, url, ip, target=None):
        try:
            if url:
                auth, headers = self._get_auth(target) if target else (None, None)
                response = requests.get(url, timeout=self.timeout, verify=False, auth=auth, headers=headers)
                return {"status": "PASS", "details": f"Status Code: {response.status_code}"}, response
            elif ip:
                sock = socket.create_connection((ip, 80), timeout=self.timeout)
                sock.close()
                return {"status": "PASS", "details": "Port 80 reachable"}, None
        except Exception as e:
            logger.error(f"Connectivity check failed for {url or ip}: {str(e)}")
            return {"status": "FAIL", "details": str(e)}, None
        return {"status": "SKIPPED", "details": "No URL or IP provided"}, None

    def check_ssl(self, host, port=443):
        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    not_after = datetime.datetime.strptime(cert['notAfter'], r'%b %d %H:%M:%S %Y %Z')
                    days_left = (not_after - datetime.datetime.utcnow()).days
                    details = {
                        "version": version,
                        "cipher": cipher[0],
                        "days_left": days_left,
                        "issuer": dict(x[0] for x in cert['issuer'])
                    }
                    min_version = self.config['ssl'].get('min_version', 'TLSv1.2')
                    if version < min_version:
                         return {"status": "FAIL", "details": f"Protocol {version} is too old (min {min_version})", "data": details}
                    if days_left < 0:
                        return {"status": "FAIL", "details": "Certificate expired", "data": details}
                    return {"status": "PASS", "details": f"Valid {version} cert, {days_left} days left", "data": details}
        except Exception as e:
            return {"status": "FAIL", "details": f"SSL Handshake failed: {str(e)}"}

    def check_headers(self, url, target=None):
        required_headers = self.config['headers'].get('required', [])
        try:
            auth, headers = self._get_auth(target) if target else (None, None)
            response = requests.get(url, timeout=self.timeout, verify=False, auth=auth, headers=headers)
            return self.check_headers_from_obj(response.headers)
        except Exception as e:
            return {"status": "FAIL", "details": f"Request failed: {str(e)}"}
            
    def check_headers_from_obj(self, headers_obj):
        required_headers = self.config['headers'].get('required', [])
        missing = []
        for h in required_headers:
            if h not in headers_obj:
                missing.append(h)
        if missing:
            return {"status": "FAIL", "details": f"Missing headers: {', '.join(missing)}"}
        return {"status": "PASS", "details": "All required headers present"}
