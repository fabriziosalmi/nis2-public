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
        self.nmap_scanner = NmapScanner(config.get('nmap', {}))
        self.dns_scanner = DNSScanner(config.get('dns', {}))
        logger.info("ScannerLogic initialized")

    def _map_result(self, check_id: str, status: str, details: str, raw_data: Dict[str, Any] = None) -> CheckResult:
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
        elif status == "PASS":
            severity = Severity.INFO # Passing checks are info/low severity usually

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

        # Connectivity Check
        if self.config['checks'].get('connectivity'):
            res = self.check_connectivity(url, ip, target)
            scan_result.results.append(self._map_result("connectivity", res['status'], res['details']))

        # Web Checks
        if target_type in ['web', 'https', 'generic']:
            if self.config['checks'].get('ssl_tls') and host:
                res = self.check_ssl(host, port)
                scan_result.results.append(self._map_result("ssl_tls", res['status'], res['details'], res.get('data')))

            if self.config['checks'].get('security_headers') and url:
                res = self.check_headers(url, target)
                scan_result.results.append(self._map_result("security_headers", res['status'], res['details']))

        # Nmap Infrastructure Checks
        nmap_raw = self.nmap_scanner.scan_target(target)
        if nmap_raw:
            for check_key, check_val in nmap_raw.items():
                # Map Nmap keys to our internal IDs
                # ssh_auth -> ssh_password_auth
                # tls_versions -> deprecated_tls
                # open_mgmt -> open_mgmt_ports
                # rdp_security -> rdp_encryption
                # smb_security -> smb_signing
                
                internal_id = check_key
                if check_key == 'ssh_auth': internal_id = 'ssh_password_auth'
                elif check_key == 'tls_versions': internal_id = 'deprecated_tls'
                elif check_key == 'open_mgmt': internal_id = 'open_mgmt_ports'
                elif check_key == 'rdp_security': internal_id = 'rdp_encryption'
                elif check_key == 'smb_security': internal_id = 'smb_signing'
                
                scan_result.results.append(self._map_result(internal_id, check_val['status'], check_val['details']))

        # DNS Checks
        if self.config.get('checks', {}).get('dns_checks', False):
             target_val = target.get('url') or target.get('ip')
             if target_val:
                 dns_raw = self.dns_scanner.scan_target(target_val)
                 for k, v in dns_raw.items():
                     # spf, dmarc, dnssec
                     internal_id = k
                     if k == 'spf': internal_id = 'spf_record'
                     elif k == 'dmarc': internal_id = 'dmarc_record'
                     
                     scan_result.results.append(self._map_result(internal_id, v['status'], v['details']))

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
                return {"status": "PASS", "details": f"Status Code: {response.status_code}"}
            elif ip:
                sock = socket.create_connection((ip, 80), timeout=self.timeout)
                sock.close()
                return {"status": "PASS", "details": "Port 80 reachable"}
        except Exception as e:
            logger.error(f"Connectivity check failed for {url or ip}: {str(e)}")
            return {"status": "FAIL", "details": str(e)}
        return {"status": "SKIPPED", "details": "No URL or IP provided"}

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
            headers = response.headers
            missing = []
            for h in required_headers:
                if h not in headers:
                    missing.append(h)
            if missing:
                return {"status": "FAIL", "details": f"Missing headers: {', '.join(missing)}"}
            return {"status": "PASS", "details": "All required headers present"}
        except Exception as e:
            return {"status": "FAIL", "details": f"Request failed: {str(e)}"}
