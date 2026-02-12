import httpx
import re
from typing import Dict, Any, List
from nis2_checker.plugins.base import ScannerPlugin
from nis2_checker.models import CheckResult, Severity
from nis2_checker.audit_mapping import AUDIT_MAPPING

class WebScannerPlugin(ScannerPlugin):
    async def scan(self, target: Dict[str, Any], context: Dict[str, Any]) -> List[CheckResult]:
        url = target.get('url')
        if not url:
            return []

        results = []
        timeout = self.config.get('timeout', 10)
        
        async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True, http2=True) as client:
            try:
                # 1. Main Content & Headers Fetch
                response = await client.get(url)
                context['response_body'] = response.text
                context['response_headers'] = response.headers
                
                # Connectivity Check
                results.append(self._create_res("connectivity", "PASS", f"Successfully reached {url}"))
                
                # Security Headers
                results.extend(self._check_headers(response.headers))
                
                # Italian Compliance (P.IVA, Privacy)
                results.extend(self._check_italian_compliance(response.text))
                
                # WAF/CDN Detection
                results.append(self._detect_waf_cdn(response.headers))
                
            except Exception as e:
                results.append(self._create_res("connectivity", "FAIL", f"Connection failed: {str(e)}"))
        
        return results

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

    def _check_headers(self, headers: Dict[str, str]) -> List[CheckResult]:
        results = []
        checks = {
            'Strict-Transport-Security': 'HSTS missing',
            'Content-Security-Policy': 'CSP missing',
            'X-Frame-Options': 'X-Frame-Options missing',
            'X-Content-Type-Options': 'X-Content-Type-Options missing'
        }
        for h, msg in checks.items():
            if h not in headers:
                 results.append(self._create_res("security_headers", "FAIL", f"Missing {h}"))
        
        if not results:
             results.append(self._create_res("security_headers", "PASS", "Essential security headers found"))
        return results

    def _check_italian_compliance(self, body: str) -> List[CheckResult]:
        results = []
        # P.IVA
        piva_regex = r"(P\.?\s*IVA|Partita\s*IVA|VAT)\s*[:.]?\s*([0-9]{11})"
        if re.search(piva_regex, body, re.IGNORECASE):
             results.append(self._create_res("piva", "PASS", "P.IVA/VAT ID found"))
        else:
             results.append(self._create_res("piva", "FAIL", "P.IVA not found (Mandatory for IT)"))
             
        # Privacy Policy
        if re.search(r"privacy\s*policy|informativa\s*privacy", body, re.IGNORECASE):
            results.append(self._create_res("privacy_policy", "PASS", "Privacy Policy found"))
        else:
            results.append(self._create_res("privacy_policy", "FAIL", "Privacy Policy missing"))
            
        return results

    def _detect_waf_cdn(self, headers: Dict[str, str]) -> CheckResult:
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        indicators = []
        if 'cf-ray' in headers_lower: indicators.append('Cloudflare')
        if 'x-amz-cf-id' in headers_lower: indicators.append('AWS CloudFront')
        
        if indicators:
            return self._create_res("waf_cdn", "PASS", f"WAF/CDN: {', '.join(indicators)}")
        return self._create_res("waf_cdn", "FAIL", "No WAF/CDN detected")
