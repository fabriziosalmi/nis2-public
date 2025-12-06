import re
import requests
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

class ComplianceScanner:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get('enabled', True)
        self.timeout = config.get('timeout', 10)

    def scan_security_txt(self, url: str) -> Dict[str, Any]:
        """Check for /.well-known/security.txt compliance (RFC 9116)."""
        if not url.startswith('http'):
            return {"status": "SKIPPED", "details": "URL required"}
            
        target_url = url.rstrip('/') + "/.well-known/security.txt"
        
        try:
            response = requests.get(target_url, timeout=self.timeout, verify=False, allow_redirects=True)
            
            if response.status_code != 200:
                return {"status": "FAIL", "details": "security.txt not found (404/other)"}
                
            content = response.text
            
            # RFC 9116 Requirements
            has_contact = "Contact:" in content
            has_expires = "Expires:" in content
            
            if has_contact and has_expires:
                return {
                    "status": "PASS", 
                    "details": "Valid security.txt found (RFC 9116 compliant)",
                    "data": {"url": target_url}
                }
            elif has_contact:
                return {
                    "status": "WARN", 
                    "details": "security.txt found but missing 'Expires' field (RFC 9116 violation)"
                }
            else:
                 return {
                    "status": "FAIL", 
                    "details": "security.txt found but missing 'Contact' field"
                }
                
        except Exception as e:
            return {"status": "WARN", "details": f"Error checking security.txt: {str(e)}"}

    def scan_italian_compliance(self, response_body: str) -> Dict[str, Any]:
        """Check for Italian mandatory website info (P.IVA, Privacy)."""
        if not response_body:
             return {"status": "SKIPPED", "details": "No content to analyze"}

        results = {}
        
        # 1. P.IVA (VAT ID) - Simple Regex for 11 digits
        # Look for "P.IVA", "Partita IVA", "VAT" followed by 11 digits
        piva_regex = r"(P\.?\s*IVA|Partita\s*IVA|VAT)\s*[:.]?\s*([0-9]{11})"
        if re.search(piva_regex, response_body, re.IGNORECASE):
             results['piva'] = {"status": "PASS", "details": "P.IVA/VAT ID found"}
        else:
             results['piva'] = {"status": "WARN", "details": "P.IVA not found on homepage (Mandatory for IT companies)"}

        # 2. Privacy Policy
        if re.search(r"privacy\s*policy|informativa\s*privacy", response_body, re.IGNORECASE):
            results['privacy_policy'] = {"status": "PASS", "details": "Privacy Policy link found"}
        else:
            results['privacy_policy'] = {"status": "FAIL", "details": "Privacy Policy link not found"}
            
        # 3. Cookie Banner / CMP
        cmp_indicators = ["iubenda", "cookiebot", "onetrust", "didomi", "usercentrics"]
        found_cmp = [cmp for cmp in cmp_indicators if cmp in response_body.lower()]
        
        if found_cmp:
            results['cookie_banner'] = {"status": "PASS", "details": f"CMP detected: {', '.join(found_cmp)}"}
        else:
            results['cookie_banner'] = {"status": "WARN", "details": "No common CMP detected (Iubenda, Cookiebot, OneTrust)"}
            
        return results

    def detect_waf_cdn(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Detect presence of WAF or CDN via headers."""
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        indicators = []
        if 'cf-ray' in headers_lower: indicators.append('Cloudflare')
        if 'server' in headers_lower and 'cloudflare' in headers_lower['server']: indicators.append('Cloudflare')
        if 'x-amz-cf-id' in headers_lower: indicators.append('AWS CloudFront')
        if 'akamai' in str(headers_lower): indicators.append('Akamai')
        
        if indicators:
            return {"status": "PASS", "details": f"WAF/CDN Protected: {', '.join(set(indicators))}"}
            
        return {"status": "WARN", "details": "No WAF/CDN headers detected (Direct exposure?)"}
