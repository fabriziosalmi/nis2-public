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
from nis2_checker.compliance_scanner import ComplianceScanner
from nis2_checker.evidence import EvidenceCollector
from nis2_checker.models import CheckResult, TargetScanResult, Severity
from nis2_checker.audit_mapping import AUDIT_MAPPING
from nis2_checker.logger import setup_logger

# 10x Plugins
from nis2_checker.plugins.web_plugin import WebScannerPlugin
from nis2_checker.plugins.compliance_plugin import CompliancePlugin
from nis2_checker.plugins.infrastructure_plugin import InfrastructurePlugin

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
        self.compliance_scanner = ComplianceScanner(config.get('compliance', {}))
        self.evidence_collector = EvidenceCollector()
        
        # 10x Improvement: Plugin-based architecture
        self.plugins = [
            WebScannerPlugin(config),
            CompliancePlugin(config),
            InfrastructurePlugin(config)
        ]
        
        logger.info("ScannerLogic initialized with Plugin-based Engine (v2)")

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

    async def scan_target(self, target: Dict[str, Any]) -> List[TargetScanResult]:
        """Run all enabled checks for a single target or CIDR using parallel plugins."""
        results = []
        
        # Check for CIDR (Recursive Async Discovery)
        ip = target.get('ip')
        if ip and '/' in ip:
            import asyncio
            live_hosts = self.nmap_scanner.discover_hosts(ip)
            tasks = [self.scan_target({**target, 'ip': host, 'name': f"{target.get('name', 'Network')} - {host}"}) for host in live_hosts]
            nested = await asyncio.gather(*tasks)
            return [item for sublist in nested for item in sublist]

        # Single Target Scan
        url = target.get('url')
        name = target.get('name', url or ip)
        logger.info(f"Scanning {name}...")
        
        scan_result = TargetScanResult(target=url or ip, name=name)
        context = {}
        
        # 1. Run All Plugins in Parallel
        import asyncio
        plugin_tasks = [plugin.scan(target, context) for plugin in self.plugins]
        plugin_results = await asyncio.gather(*plugin_tasks)
        
        for res_list in plugin_results:
            scan_result.results.extend(res_list)

        # 2. Content Analysis (Dynamic context enrichment)
        response_body = context.get('response_body')
        response_headers = context.get('response_headers')
        
        if response_body:
            content_res = self.content_scanner.scan_content(response_headers or {}, response_body)
            for k, v in content_res.items():
                 sev = Severity.CRITICAL if k == 'secrets_leak' and v['status'] == 'FAIL' else Severity.HIGH
                 scan_result.results.append(self._map_result(k, v['status'], v['details'], severity_override=sev))

        # 3. Nmap Checks (Wrapped in to_thread as they are subprocess heavy)
        if self.config.get('nmap', {}).get('enabled'):
             nmap_raw = await asyncio.to_thread(self.nmap_scanner.scan_target, target)
             for k, v in nmap_raw.items():
                  scan_result.results.append(self._map_result(k, v['status'], v['details']))

        # 4. Evidence
        if self.config.get('checks', {}).get('evidence') and url:
             screenshot_path = await asyncio.to_thread(self.evidence_collector.take_screenshot, url, name)
             if screenshot_path:
                  scan_result.results.append(self._map_result("evidence_collected", "PASS", f"Screenshot: {screenshot_path}"))

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
