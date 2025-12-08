"""
Regional and Legal Compliance Checks
Validates security.txt, Italian P.IVA, Privacy Policy, Cookie Banners
"""
import re
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger("nis2scan")

class LegalChecker:
    """Handles regional/legal compliance checks"""
    
    def __init__(self):
        # Italian P.IVA regex: 11 digits
        self.piva_pattern = re.compile(r'P\.?\s*IVA:?\s*(\d{11})')
        
        # Privacy policy keywords (case insensitive)
        self.privacy_keywords = ['privacy policy', 'informativa privacy', 'privacy']
        
        # Cookie banner keywords (multilingual)
        self.cookie_keywords = [
            'cookie', 'accetta', 'accetto', 'consenso', 'accept cookies',
            'cookie policy', 'gestisci cookie', 'manage cookies'
        ]
    
    def check_security_txt(self, url: str, http_response: Optional[str]) -> Dict[str, Any]:
        """
        Check for security.txt (RFC 9116)
        Returns: {found: bool, url: str, content_preview: str}
        """
        result = {
            "found": False,
            "url": f"{url}/.well-known/security.txt",
            "content_preview": ""
        }
        
        # This would require a dedicated HTTP request to /.well-known/security.txt
        # For now, we'll mark it as a placeholder that needs implementation
        # in the scanner's HTTP check phase
        
        return result
    
    def check_italian_requirements(self, html_body: str) -> Dict[str, Any]:
        """
        Check for Italian legal requirements:
        - P.IVA (VAT number)
        - Privacy Policy link
        """
        result = {
            "piva_found": False,
            "piva_value": None,
            "privacy_policy_found": False
        }
        
        # Check P.IVA
        piva_match = self.piva_pattern.search(html_body)
        if piva_match:
            result["piva_found"] = True
            result["piva_value"] = piva_match.group(1)
        
        # Check Privacy Policy (case insensitive)
        html_lower = html_body.lower()
        for keyword in self.privacy_keywords:
            if keyword in html_lower:
                result["privacy_policy_found"] = True
                break
        
        return result
    
    def check_cookie_banner(self, html_body: str) -> Dict[str, Any]:
        """
        Detect cookie consent banner presence
        """
        result = {
            "banner_detected": False,
            "matched_keywords": []
        }
        
        html_lower = html_body.lower()
        for keyword in self.cookie_keywords:
            if keyword in html_lower:
                result["banner_detected"] = True
                result["matched_keywords"].append(keyword)
        
        return result
    
    def analyze_page(self, url: str, html_body: str) -> Dict[str, Any]:
        """
        Run all legal checks on a page
        """
        return {
            "url": url,
            "italian_compliance": self.check_italian_requirements(html_body),
            "cookie_banner": self.check_cookie_banner(html_body),
            # security.txt requires separate request, handled in scanner
        }
