import asyncio
import socket
import ssl
import datetime
from typing import Dict, Any, List
from nis2_checker.plugins.base import ScannerPlugin
from nis2_checker.models import CheckResult, Severity
from nis2_checker.audit_mapping import AUDIT_MAPPING

class InfrastructurePlugin(ScannerPlugin):
    async def scan(self, target: Dict[str, Any], context: Dict[str, Any]) -> List[CheckResult]:
        ip = target.get('ip')
        url = target.get('url')
        results = []
        
        # Determine host/port
        host = None
        port = 443
        if url:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.hostname
            if parsed.port: port = parsed.port
        elif ip:
            host = ip

        if not host:
            return []

        # DNS Check
        if self.config.get('checks', {}).get('dns_checks'):
            results.extend(await self._scan_dns(host))
            
        # SSL Scan
        if self.config.get('checks', {}).get('ssl_tls') and port in [443, 8443]:
            results.append(await self._scan_ssl(host, port))
            
        return results

    async def _scan_dns(self, host: str) -> List[CheckResult]:
        import dns.resolver
        res = []
        checks = ['SPF', 'DMARC']
        for check in checks:
            try:
                # Basic sync-to-async wrap for dns.resolver
                loop = asyncio.get_event_loop()
                query_host = host if check == 'SPF' else f"_dmarc.{host}"
                qtype = 'TXT'
                await loop.run_in_executor(None, dns.resolver.resolve, query_host, qtype)
                res.append(self._create_res(f"{check.lower()}_record", "PASS", f"{check} record found"))
            except Exception:
                res.append(self._create_res(f"{check.lower()}_record", "FAIL", f"{check} record missing"))
        return res

    async def _scan_ssl(self, host, port) -> CheckResult:
        loop = asyncio.get_event_loop()
        try:
            # Wrap synchronous SSL logic
            data = await loop.run_in_executor(None, self._check_ssl_sync, host, port)
            return self._create_res("ssl_tls", data['status'], data['details'])
        except Exception as e:
            return self._create_res("ssl_tls", "FAIL", f"SSL/TLS error: {str(e)}")

    def _check_ssl_sync(self, host, port):
        context = ssl.create_default_context()
        timeout = self.config.get('timeout', 10)
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
                not_after = datetime.datetime.strptime(cert['notAfter'], r'%b %d %H:%M:%S %Y %Z')
                days_left = (not_after - datetime.datetime.utcnow()).days
                
                if days_left < 30:
                     return {"status": "FAIL", "details": f"Certificate expires in {days_left} days"}
                if version < "TLSv1.2":
                     return {"status": "FAIL", "details": f"Deprecated TLS version: {version}"}
                return {"status": "PASS", "details": f"SSL/TLS OK ({version})"}

    def _create_res(self, check_id: str, status: str, details: str) -> CheckResult:
        mapping = AUDIT_MAPPING.get(check_id, {"name": check_id, "article": "Unknown", "severity_fail": Severity.LOW, "remediation": "Check manually."})
        return CheckResult(
            check_id=check_id,
            name=mapping["name"],
            status=status,
            details=details,
            severity=mapping["severity_fail"] if status == "FAIL" else Severity.INFO,
            nis2_article=mapping["article"],
            remediation=mapping["remediation"] if status == "FAIL" else None
        )
