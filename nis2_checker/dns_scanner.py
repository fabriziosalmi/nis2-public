import dns.resolver
import dns.exception
from urllib.parse import urlparse
from typing import Dict, Any, Optional

class DNSScanner:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.resolver = dns.resolver.Resolver()
        # Set timeout from config or default to 5 seconds
        timeout = config.get('timeout', 5)
        self.resolver.lifetime = timeout
        self.resolver.timeout = timeout

    def _extract_domain(self, target: str) -> str:
        """Extract domain from URL or return as is if it looks like a domain/IP."""
        if "://" in target:
            parsed = urlparse(target)
            return parsed.netloc.split(':')[0] # Remove port if present
        return target.split(':')[0]

    def scan_target(self, target: str) -> Dict[str, Any]:
        """Run configured DNS checks on the target."""
        domain = self._extract_domain(target)
        results = {}
        
        checks_config = self.config.get('checks', {})

        if checks_config.get('email_security', True):
            results['spf'] = self._check_spf(domain)
            results['dmarc'] = self._check_dmarc(domain)

        if checks_config.get('dns_security', True):
            results['dnssec'] = self._check_dnssec(domain)

        return results

    def _check_spf(self, domain: str) -> Dict[str, str]:
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt_record = rdata.to_text().strip('"')
                if txt_record.startswith('v=spf1'):
                    return {
                        "status": "PASS",
                        "details": f"SPF record found: {txt_record}"
                    }
            return {
                "status": "FAIL",
                "details": "No SPF record found (v=spf1)"
            }
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return {
                "status": "FAIL",
                "details": "No TXT records found or domain does not exist"
            }
        except Exception as e:
            return {
                "status": "FAIL",
                "details": f"Error checking SPF: {str(e)}"
            }

    def _check_dmarc(self, domain: str) -> Dict[str, str]:
        dmarc_domain = f"_dmarc.{domain}"
        try:
            answers = self.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                txt_record = rdata.to_text().strip('"')
                if txt_record.startswith('v=DMARC1'):
                    return {
                        "status": "PASS",
                        "details": f"DMARC record found: {txt_record}"
                    }
            return {
                "status": "FAIL",
                "details": "No DMARC record found (v=DMARC1)"
            }
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return {
                "status": "FAIL",
                "details": f"No DMARC record found at {dmarc_domain}"
            }
        except Exception as e:
            return {
                "status": "FAIL",
                "details": f"Error checking DMARC: {str(e)}"
            }

    def _check_dnssec(self, domain: str) -> Dict[str, str]:
        try:
            # Check for DNSKEY records
            self.resolver.resolve(domain, 'DNSKEY')
            return {
                "status": "PASS",
                "details": "DNSKEY records found (DNSSEC likely enabled)"
            }
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
             return {
                "status": "FAIL",
                "details": "No DNSKEY records found"
            }
        except Exception as e:
            return {
                "status": "FAIL",
                "details": f"Error checking DNSSEC: {str(e)}"
            }
