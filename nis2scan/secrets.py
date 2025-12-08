"""
Secrets Detection and WHOIS Monitoring
Scans for leaked credentials and monitors domain expiry
"""
import re
import logging
from typing import List, Dict, Any
from datetime import datetime, timedelta

logger = logging.getLogger("nis2scan")

class SecretsDetector:
    """Detects leaked secrets in HTTP responses"""
    
    def __init__(self):
        # Regex patterns for common secrets
        self.patterns = {
            'aws_access_key': re.compile(r'AKIA[0-9A-Z]{16}'),
            'aws_secret_key': re.compile(r'aws_secret_access_key\s*=\s*["\']?([A-Za-z0-9/+=]{40})["\']?'),
            'private_key': re.compile(r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----'),
            'github_token': re.compile(r'ghp_[a-zA-Z0-9]{36}'),
            'generic_api_key': re.compile(r'api[_-]?key\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', re.IGNORECASE),
            'jwt_token': re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'),
        }
    
    def scan_content(self, content: str, source: str = "unknown") -> List[Dict[str, Any]]:
        """
        Scan content for leaked secrets
        Returns list of findings
        """
        findings = []
        
        for secret_type, pattern in self.patterns.items():
            matches = pattern.finditer(content)
            for match in matches:
                findings.append({
                    "type": secret_type,
                    "source": source,
                    "preview": match.group(0)[:50] + "...",  # Truncate for safety
                    "position": match.start()
                })
        
        return findings

class WHOISMonitor:
    """Monitors domain expiration dates"""
    
    def __init__(self, warning_days: int = 30):
        self.warning_days = warning_days
    
    def check_domain_expiry(self, domain: str) -> Dict[str, Any]:
        """
        Check domain expiration date using python-whois
        Returns: {domain, expiry_date, days_remaining, warning}
        """
        result = {
            "domain": domain,
            "expiry_date": None,
            "days_remaining": None,
            "warning": False,
            "error": None
        }
        
        try:
            import whois
            w = whois.whois(domain)
            
            # Handle both single date and list of dates
            expiry = w.expiration_date
            if isinstance(expiry, list):
                expiry = expiry[0]
            
            if expiry:
                result["expiry_date"] = expiry.isoformat() if hasattr(expiry, 'isoformat') else str(expiry)
                
                # Calculate days remaining
                if isinstance(expiry, datetime):
                    days_left = (expiry - datetime.now()).days
                    result["days_remaining"] = days_left
                    
                    if days_left < self.warning_days:
                        result["warning"] = True
        
        except ImportError:
            result["error"] = "python-whois not installed"
            logger.warning("python-whois not installed. Install with: pip install python-whois")
        except Exception as e:
            result["error"] = str(e)
            logger.debug(f"WHOIS lookup failed for {domain}: {e}")
        
        return result
