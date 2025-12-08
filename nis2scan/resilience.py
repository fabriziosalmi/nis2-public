"""
Resilience and Security Hardening Checks
Detects WAF/CDN, analyzes service banners
"""
import re
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("nis2scan")

class ResilienceChecker:
    """Detects WAF/CDN and security hardening measures"""
    
    def __init__(self):
        # WAF/CDN detection patterns
        self.waf_indicators = {
            'cloudflare': ['cf-ray', 'cloudflare', '__cfduid'],
            'akamai': ['akamai', 'x-akamai', 'akamaighost'],
            'aws_cloudfront': ['x-amz-cf-id', 'cloudfront'],
            'fastly': ['fastly', 'x-fastly'],
            'incapsula': ['incap_ses', 'visid_incap'],
            'sucuri': ['x-sucuri-id', 'sucuri']
        }
    
    def detect_waf_cdn(self, headers: Dict[str, str], cookies: str = "") -> Dict[str, Any]:
        """
        Analyze HTTP headers and cookies for WAF/CDN presence
        """
        result = {
            "protected": False,
            "providers": [],
            "confidence": "none"
        }
        
        # Convert headers to lowercase for case-insensitive matching
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        cookies_lower = cookies.lower()
        
        detected = []
        for provider, indicators in self.waf_indicators.items():
            for indicator in indicators:
                # Check headers
                if any(indicator in key or indicator in value 
                       for key, value in headers_lower.items()):
                    detected.append(provider)
                    break
                # Check cookies
                if indicator in cookies_lower:
                    detected.append(provider)
                    break
        
        if detected:
            result["protected"] = True
            result["providers"] = list(set(detected))  # Remove duplicates
            result["confidence"] = "high" if len(detected) > 1 else "medium"
        
        return result
    
    def analyze_banner(self, banner: str, service: str) -> Dict[str, Any]:
        """
        Analyze service banner for security issues
        Returns warnings if banner reveals too much info
        """
        result = {
            "service": service,
            "banner": banner[:100],  # Truncate for safety
            "issues": []
        }
        
        # Check for version disclosure
        version_patterns = [
            r'\d+\.\d+\.\d+',  # Semantic versioning
            r'version\s+\d+',
            r'v\d+\.\d+'
        ]
        
        for pattern in version_patterns:
            if re.search(pattern, banner, re.IGNORECASE):
                result["issues"].append("Version information disclosed")
                break
        
        # Check for OS disclosure
        os_keywords = ['ubuntu', 'debian', 'centos', 'windows', 'linux']
        banner_lower = banner.lower()
        for os_name in os_keywords:
            if os_name in banner_lower:
                result["issues"].append(f"OS information disclosed ({os_name})")
                break
        
        return result
    
    def check_ssh_hardening(self, banner: str) -> Dict[str, Any]:
        """
        Specific checks for SSH hardening
        """
        result = {
            "protocol_version": None,
            "warnings": []
        }
        
        # Extract SSH protocol version
        ssh_match = re.search(r'SSH-(\d+\.\d+)', banner)
        if ssh_match:
            result["protocol_version"] = ssh_match.group(1)
            
            # Warn if using old protocol
            if ssh_match.group(1) == "1.0" or ssh_match.group(1) == "1.5":
                result["warnings"].append("Outdated SSH protocol version")
        
        # Check for common weak configurations (would need actual connection)
        # This is a placeholder for banner-based detection
        if "password" in banner.lower():
            result["warnings"].append("Possible password authentication enabled")
        
        return result
