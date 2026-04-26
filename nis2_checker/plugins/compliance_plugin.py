import httpx
from typing import Dict, Any, List
from nis2_checker.plugins.base import ScannerPlugin
from nis2_checker.models import CheckResult, Severity
from nis2_checker.audit_mapping import AUDIT_MAPPING

class CompliancePlugin(ScannerPlugin):
    async def scan(self, target: Dict[str, Any], context: Dict[str, Any]) -> List[CheckResult]:
        url = target.get('url')
        if not url:
            return []

        results = []
        timeout = self.config.get('timeout', 10)
        
        async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
            # 1. security.txt Check
            results.append(await self._check_security_txt(client, url))
            
        return results

    async def _check_security_txt(self, client, url: str) -> CheckResult:
        target_url = url.rstrip('/') + "/.well-known/security.txt"
        try:
            response = await client.get(target_url)
            if response.status_code == 200:
                content = response.text
                if "Contact:" in content and "Expires:" in content:
                    return self._create_res("security_txt", "PASS", "Valid security.txt found")
                elif "Contact:" in content:
                    return self._create_res("security_txt", "WARN", "security.txt missing 'Expires' field")
            return self._create_res("security_txt", "FAIL", "security.txt not found or invalid")
        except Exception as e:
            return self._create_res("security_txt", "FAIL", f"Error checking security.txt: {str(e)}")

    def _create_res(self, check_id: str, status: str, details: str) -> CheckResult:
        mapping = AUDIT_MAPPING.get(check_id, {"name": check_id, "article": "Unknown", "severity_fail": Severity.LOW, "remediation": "Check manually."})
        severity = mapping["severity_fail"] if status == "FAIL" else Severity.INFO
        if status == "WARN": severity = Severity.MEDIUM
        
        return CheckResult(
            check_id=check_id,
            name=mapping["name"],
            status=status,
            details=details,
            severity=severity,
            nis2_article=mapping["article"],
            remediation=mapping["remediation"] if status != "PASS" else None
        )
