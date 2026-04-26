import whois
from datetime import datetime
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

class WhoisScanner:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get('enabled', True)

    def check_domain_expiry(self, domain: str) -> Dict[str, Any]:
        """Check domain expiration date via WHOIS."""
        if not self.enabled:
             return {"status": "SKIPPED", "details": "WHOIS check disabled"}
            
        try:
            w = whois.whois(domain)
            
            # expiration_date can be a list or single date
            expiry_date = w.expiration_date
            
            if isinstance(expiry_date, list):
                expiry_date = expiry_date[0]
            
            if not expiry_date:
                return {"status": "WARN", "details": "Could not retrieve expiration date"}
                
            # Ensure expiry_date is offset-naive or convert datetime.now() to match
            if expiry_date.tzinfo is not None:
                expiry_date = expiry_date.replace(tzinfo=None) # Simplest fix: make it naive
                
            days_to_expire = (expiry_date - datetime.now()).days
            
            status = "PASS"
            details = f"Expires in {days_to_expire} days ({expiry_date.strftime('%Y-%m-%d')})"
            
            if days_to_expire < 0:
                status = "FAIL"
                details = f"Domain EXPIRED {abs(days_to_expire)} days ago!"
            elif days_to_expire < 30:
                status = "FAIL"
                details = f"Domain expires in {days_to_expire} days (Critical < 30)"
            elif days_to_expire < 60:
                status = "WARN"
                details = f"Domain expires in {days_to_expire} days (Warning < 60)"
                
            return {
                "status": status,
                "details": details,
                "data": {
                    "registrar": w.registrar,
                    "expiration_date": expiry_date.isoformat(),
                    "days_left": days_to_expire
                }
            }
            
        except Exception as e:
            logger.error(f"WHOIS check failed for {domain}: {e}")
            return {"status": "WARN", "details": f"WHOIS lookup failed: {str(e)}"}
