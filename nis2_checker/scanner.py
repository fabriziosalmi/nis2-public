import requests
import ssl
import socket
import datetime
import os
from urllib.parse import urlparse
import urllib3
from nis2_checker.nmap_scanner import NmapScanner

# Disable warnings for self-signed certs if needed (though we want to check them)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Scanner:
    def __init__(self, config):
        self.config = config
        self.timeout = config.get('timeout', 10)
        self.results = []
        self.nmap_scanner = NmapScanner(config)

    def scan_target(self, target):
        """Run all enabled checks for a single target or CIDR."""
        results = []
        
        # Check for CIDR
        ip = target.get('ip')
        if ip and '/' in ip:
            print(f"Discovering hosts in network {ip}...")
            live_hosts = self.nmap_scanner.discover_hosts(ip)
            print(f"Found {len(live_hosts)} live hosts: {', '.join(live_hosts)}")
            
            for host in live_hosts:
                # Create a sub-target for each host
                sub_target = target.copy()
                sub_target['ip'] = host
                sub_target['name'] = f"{target.get('name', 'Network')} - {host}"
                # Recursively scan (but ensure we don't loop if logic is flawed)
                # Since sub_target ip won't have '/', it will fall through to single host scan
                results.extend(self.scan_target(sub_target))
            return results

        # Single Target Scan
        url = target.get('url')
        name = target.get('name', url or ip)
        
        print(f"Scanning {name} ({url or ip})...")
        
        target_result = {
            "name": name,
            "target": url or ip,
            "checks": {}
        }

        # Determine target host for socket connections
        host = None
        port = 443
        if url:
            parsed = urlparse(url)
            host = parsed.hostname
            if parsed.port:
                port = parsed.port
        elif ip:
            host = ip

        target_type = target.get('type', 'generic')

        # Connectivity Check
        if self.config['checks'].get('connectivity'):
            target_result['checks']['connectivity'] = self.check_connectivity(url, ip, target)

        # Web Checks (SSL, Headers) - Only for web/https/generic
        if target_type in ['web', 'https', 'generic']:
            # SSL/TLS Check
            if self.config['checks'].get('ssl_tls') and host:
                target_result['checks']['ssl_tls'] = self.check_ssl(host, port)

            # Security Headers Check
            if self.config['checks'].get('security_headers') and url:
                target_result['checks']['security_headers'] = self.check_headers(url, target)

        # Nmap Infrastructure Checks
        nmap_results = self.nmap_scanner.scan_target(target)
        if nmap_results:
            target_result['checks'].update(nmap_results)

        results.append(target_result)
        return results

    def _get_auth(self, target):
        """Retrieve authentication credentials from env vars."""
        auth_id = target.get('auth_id')
        if not auth_id:
            return None, None

        # Try to find env var for token or basic auth
        # Convention: {AUTH_ID}_TOKEN or {AUTH_ID}_USER / {AUTH_ID}_PASS
        token = os.environ.get(f"{auth_id}_TOKEN")
        if token:
            return None, {"Authorization": f"Bearer {token}"}
        
        user = os.environ.get(f"{auth_id}_USER")
        password = os.environ.get(f"{auth_id}_PASS")
        if user and password:
            return (user, password), None
            
        return None, None

    def check_connectivity(self, url, ip, target=None):
        """Check if the target is reachable."""
        try:
            if url:
                auth, headers = self._get_auth(target) if target else (None, None)
                response = requests.get(url, timeout=self.timeout, verify=False, auth=auth, headers=headers)
                return {"status": "PASS", "details": f"Status Code: {response.status_code}"}
            elif ip:
                # Simple ping or socket connect
                sock = socket.create_connection((ip, 80), timeout=self.timeout)
                sock.close()
                return {"status": "PASS", "details": "Port 80 reachable"}
        except Exception as e:
            return {"status": "FAIL", "details": str(e)}
        return {"status": "SKIPPED", "details": "No URL or IP provided"}

    def check_ssl(self, host, port=443):
        """Check SSL/TLS configuration."""
        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Check expiry
                    not_after = datetime.datetime.strptime(cert['notAfter'], r'%b %d %H:%M:%S %Y %Z')
                    days_left = (not_after - datetime.datetime.utcnow()).days
                    
                    details = {
                        "version": version,
                        "cipher": cipher[0],
                        "days_left": days_left,
                        "issuer": dict(x[0] for x in cert['issuer'])
                    }

                    # Basic compliance logic
                    min_version = self.config['ssl'].get('min_version', 'TLSv1.2')
                    # Simple string comparison works for TLSv1.2 vs TLSv1.3 but not perfect
                    if version < min_version:
                         return {"status": "FAIL", "details": f"Protocol {version} is too old (min {min_version})", "data": details}
                    
                    if days_left < 0:
                        return {"status": "FAIL", "details": "Certificate expired", "data": details}
                    
                    return {"status": "PASS", "details": f"Valid {version} cert, {days_left} days left", "data": details}

        except Exception as e:
            return {"status": "FAIL", "details": f"SSL Handshake failed: {str(e)}"}

    def check_headers(self, url, target=None):
        """Check for security headers."""
        required_headers = self.config['headers'].get('required', [])
        try:
            auth, headers = self._get_auth(target) if target else (None, None)
            response = requests.get(url, timeout=self.timeout, verify=False, auth=auth, headers=headers)
            headers = response.headers
            
            missing = []
            for h in required_headers:
                if h not in headers:
                    missing.append(h)
            
            if missing:
                return {"status": "FAIL", "details": f"Missing headers: {', '.join(missing)}"}
            
            return {"status": "PASS", "details": "All required headers present"}
            
        except Exception as e:
            return {"status": "FAIL", "details": f"Request failed: {str(e)}"}
