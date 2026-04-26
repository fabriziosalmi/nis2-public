import subprocess
import shutil
import sys

class NmapScanner:
    def __init__(self, config):
        self.config = config.get('nmap', {})
        self.enabled = self.config.get('enabled', False)
        self.nmap_path = shutil.which("nmap")

    def check_nmap_installed(self):
        return self.nmap_path is not None

    def scan_target(self, target):
        if not self.enabled or not self.check_nmap_installed():
            return {}

        ip = target.get('ip')
        url = target.get('url')
        target_type = target.get('type', 'generic') # web, ssh, windows, generic
        
        # Resolve URL to IP if needed, or let nmap handle hostname
        target_host = ip
        if not target_host and url:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            target_host = parsed.hostname

        if not target_host:
            return {"status": "SKIPPED", "details": "No host to scan"}

        results = {}
        
        # Dispatch checks based on type
        
        # SSH Checks (ssh, generic)
        if target_type in ['ssh', 'generic'] and self.config['checks'].get('ssh_password'):
            results['ssh_auth'] = self._check_ssh_auth(target_host)

        # Web/TLS Checks (web, https, generic)
        if target_type in ['web', 'https', 'generic']:
            if self.config['checks'].get('tls_deprecated'):
                results['tls_infra'] = self._check_tls_infra(target_host)
            if self.config['checks'].get('http_cleartext'):
                results['http_mgmt'] = self._check_http_mgmt(target_host)

        # Windows Checks (windows)
        if target_type == 'windows':
            if self.config['checks'].get('windows_rdp'):
                results['rdp_security'] = self._check_rdp_security(target_host)
            if self.config['checks'].get('windows_smb'):
                results['smb_security'] = self._check_smb_security(target_host)
        
        # Vulnerability Scan (all types if enabled)
        if self.config.get('vuln_scan_enabled', False):
             results['vulnerabilities'] = self._check_vulners(target_host)

        return results

    def discover_hosts(self, cidr):
        """Perform a ping scan to discover live hosts in a CIDR."""
        if not self.enabled or not self.check_nmap_installed():
            return []
            
        # -sn: Ping Scan - disable port scan
        # -n: Never do DNS resolution (faster)
        output = self._run_nmap(["-sn", "-n", cidr])
        
        live_hosts = []
        for line in output.splitlines():
            if "Nmap scan report for" in line:
                parts = line.split()
                if len(parts) >= 5:
                    live_hosts.append(parts[-1].strip("()"))
        
        return live_hosts

    def _run_nmap(self, args):
        try:
            timing = self.config.get('timing', 3)
            cmd = [self.nmap_path, f"-T{timing}"] + args
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300) # Increased timeout for networks
            return result.stdout
        except Exception as e:
            return f"Error running nmap: {str(e)}"

    def _check_ssh_auth(self, host):
        port = self.config['ports'].get('ssh', 22)
        output = self._run_nmap(["-p", str(port), "--script", "ssh-auth-methods", host])
        
        if "password" in output:
            return {"status": "FAIL", "details": "SSH Password Authentication enabled (CRITICAL)"}
        elif "publickey" in output:
            return {"status": "PASS", "details": "SSH Public Key Authentication enabled"}
        elif "closed" in output or "filtered" in output:
             return {"status": "PASS", "details": "SSH Port closed/filtered"}
        
        return {"status": "WARN", "details": "Could not determine SSH auth method"}

    def _check_tls_infra(self, host):
        port = self.config['ports'].get('https', 443)
        output = self._run_nmap(["-p", str(port), "--script", "ssl-enum-ciphers", host])
        
        if "TLSv1.0" in output or "TLSv1.1" in output:
            return {"status": "FAIL", "details": "Deprecated TLS 1.0/1.1 detected"}
        elif "TLSv1.2" in output or "TLSv1.3" in output:
            return {"status": "PASS", "details": "Modern TLS detected"}
        elif "closed" in output or "filtered" in output:
             return {"status": "PASS", "details": "HTTPS Port closed/filtered"}

        return {"status": "WARN", "details": "Could not determine TLS version"}

    def _check_http_mgmt(self, host):
        ports = self.config['ports'].get('http_mgmt', [80, 8080])
        ports_str = ",".join(map(str, ports))
        output = self._run_nmap(["-p", ports_str, "--open", host])
        
        open_ports = []
        for port in ports:
            if f"{port}/tcp open" in output:
                open_ports.append(str(port))
        
        if open_ports:
            return {"status": "FAIL", "details": f"Cleartext HTTP management ports open: {', '.join(open_ports)}"}
        
        return {"status": "PASS", "details": "No cleartext management ports found"}

    def _check_rdp_security(self, host):
        port = self.config['ports'].get('rdp', 3389)
        output = self._run_nmap(["-p", str(port), "--script", "rdp-enum-encryption", host])
        
        if "CredSSP" in output or "SSL" in output:
             return {"status": "PASS", "details": "RDP NLA/SSL enabled"}
        elif "RDP" in output: # Standard RDP security is weak
             return {"status": "WARN", "details": "Standard RDP Security detected (Consider NLA)"}
        elif "closed" in output or "filtered" in output:
             return {"status": "PASS", "details": "RDP Port closed/filtered"}
             
        return {"status": "WARN", "details": "Could not determine RDP security"}

    def _check_smb_security(self, host):
        port = self.config['ports'].get('smb', 445)
        output = self._run_nmap(["-p", str(port), "--script", "smb-security-mode", host])
        
        if "message_signing: required" in output:
            return {"status": "PASS", "details": "SMB Signing Required"}
        elif "message_signing: disabled" in output:
            return {"status": "FAIL", "details": "SMB Signing Disabled (CRITICAL)"}
        elif "closed" in output or "filtered" in output:
             return {"status": "PASS", "details": "SMB Port closed/filtered"}

        return {"status": "WARN", "details": "Could not determine SMB security"}

    def _check_vulners(self, host):
        """Run vulners script to detect CVEs."""
        # Note: This requires the 'vulners' script to be installed in nmap
        # usually in /usr/share/nmap/scripts/vulners.nse
        # Trigger matches on CVEs with CVSS > 7.0
        
        # We need version detection (-sV) for vulners to work well
        output = self._run_nmap(["-sV", "--script", "vulners", host])
        
        cves = []
        lines = output.splitlines()
        for line in lines:
            if "CVE-" in line:
                # Basic parsing: look for CVE-YYYY-NNNN
                # Example line: |       CVE-2014-0160    5.0    https://vulners.com/cve/CVE-2014-0160
                parts = line.split()
                for part in parts:
                    if part.startswith("CVE-"):
                        cves.append(part)
        
        # Deduplicate
        cves = list(set(cves))
        
        if cves:
             return {"status": "FAIL", "details": f"Vulnerabilities found: {', '.join(cves[:5])}" + (f" and {len(cves)-5} more" if len(cves) > 5 else "")}
        
        return {"status": "PASS", "details": "No known CVEs found (vulners)"}
