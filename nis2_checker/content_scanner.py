import re
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

class ContentScanner:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.secrets_enabled = config.get('secrets_check', True)
        self.tech_enabled = config.get('tech_check', True)
        
        # Regex patterns for secrets
        self.secret_patterns = {
            "aws_key": r"AKIA[0-9A-Z]{16}",
            "private_key": r"-----BEGIN PRIVATE KEY-----",
            "generic_api": r"api_key=['\"]([a-zA-Z0-9]{32,})['\"]",
            "google_api": r"AIza[0-9A-Za-z\\-_]{35}",
            "slack_token": r"xox[baprs]-([0-9a-zA-Z]{10,48})"
        }
        
    def scan_content(self, headers: Dict, body: str) -> Dict[str, Any]:
        """Run content checks: Secrets and Tech Stack."""
        results = {}
        
        if self.secrets_enabled and body:
            results['secrets_leak'] = self._check_secrets(body)
            
        if self.tech_enabled:
            results['tech_stack'] = self._check_tech_stack(headers, body)
            
        return results

    def _check_secrets(self, body: str) -> Dict[str, Any]:
        leaks = []
        for name, pattern in self.secret_patterns.items():
            if re.search(pattern, body):
                leaks.append(name)
        
        if leaks:
            return {
                "status": "FAIL",
                "details": f"Potential secrets leaked: {', '.join(leaks)}",
                "severity": "CRITICAL"
            }
        return {"status": "PASS", "details": "No secrets found in response body"}

    def _check_tech_stack(self, headers: Dict, body: str) -> Dict[str, Any]:
        issues = []
        
        # Check Server Header
        server = headers.get('Server', '')
        if 'nginx/1.' in server:
            # Rudimentary version check 
            try:
                version = server.split('/')[1]
                major, minor = map(int, version.split('.')[:2])
                if major == 1 and minor < 18:
                     issues.append(f"Obsolete Nginx version: {server}")
            except:
                pass # Parse error
        
        # Check X-Powered-By
        x_powered = headers.get('X-Powered-By', '')
        if 'PHP/5' in x_powered or 'PHP/7.0' in x_powered or 'PHP/7.1' in x_powered:
             issues.append(f"Obsolete PHP version: {x_powered} (CRITICAL)")
             
        # Check jQuery in body (simple string match for now, ideally regex)
        # Assuming script tags like jquery-1.12.4.min.js
        if body:
            jquery_match = re.search(r"jquery[.-]([0-9]+\.[0-9]+\.[0-9]+)", body.lower())
            if jquery_match:
                version = jquery_match.group(1)
                if version.startswith('1.') or version.startswith('2.'):
                     issues.append(f"Vulnerable jQuery version: {version}")

        if issues:
            return {
                "status": "FAIL",
                "details": "; ".join(issues),
                "severity": "HIGH"
            }
            
        return {"status": "PASS", "details": "No obvious obsolete tech stack found"}
