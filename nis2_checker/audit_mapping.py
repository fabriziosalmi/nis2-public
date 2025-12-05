from .models import Severity

# Mapping of Check IDs to NIS2 Context
AUDIT_MAPPING = {
    "ssl_tls": {
        "name": "SSL/TLS Configuration",
        "article": "Art. 21.2.d - Supply chain security & Cryptography",
        "severity_fail": Severity.HIGH,
        "remediation": "Upgrade to TLS 1.2 or 1.3. Disable deprecated protocols (SSLv3, TLS 1.0, 1.1). Ensure valid certificates."
    },
    "security_headers": {
        "name": "HTTP Security Headers",
        "article": "Art. 21.2.f - Basic cyber hygiene practices",
        "severity_fail": Severity.MEDIUM,
        "remediation": "Configure web server to send security headers: HSTS, X-Frame-Options, X-Content-Type-Options, CSP."
    },
    "ssh_password_auth": {
        "name": "SSH Password Authentication",
        "article": "Art. 21.2.g - Cryptography and encryption",
        "severity_fail": Severity.CRITICAL,
        "remediation": "Disable 'PasswordAuthentication' in sshd_config. Use SSH keys for authentication."
    },
    "open_mgmt_ports": {
        "name": "Open Management Ports",
        "article": "Art. 21.2.f - Basic cyber hygiene practices",
        "severity_fail": Severity.HIGH,
        "remediation": "Close ports 80, 8080, 23 (Telnet) to the public internet. Use VPN or SSH tunnels for management."
    },
    "deprecated_tls": {
        "name": "Deprecated TLS Versions",
        "article": "Art. 21.2.d - Supply chain security & Cryptography",
        "severity_fail": Severity.HIGH,
        "remediation": "Disable TLS 1.0 and 1.1 in web server and application configurations."
    },
    "spf_record": {
        "name": "SPF Record",
        "article": "Art. 21.2.f - Basic cyber hygiene practices (Email Security)",
        "severity_fail": Severity.MEDIUM,
        "remediation": "Configure a valid SPF record (TXT) in DNS to authorize senders."
    },
    "dmarc_record": {
        "name": "DMARC Record",
        "article": "Art. 21.2.f - Basic cyber hygiene practices (Email Security)",
        "severity_fail": Severity.MEDIUM,
        "remediation": "Configure a DMARC record (TXT) in DNS with at least 'p=none' (monitoring) or 'p=quarantine/reject'."
    },
    "dnssec": {
        "name": "DNSSEC Signing",
        "article": "Art. 21.2.d - Supply chain security (DNS Integrity)",
        "severity_fail": Severity.LOW,
        "remediation": "Enable DNSSEC signing at your DNS registrar and provider."
    },
    "rdp_encryption": {
        "name": "RDP Encryption",
        "article": "Art. 21.2.g - Cryptography and encryption",
        "severity_fail": Severity.HIGH,
        "remediation": "Enforce High Encryption level for RDP. Do not expose RDP directly to the internet."
    },
    "smb_signing": {
        "name": "SMB Signing",
        "article": "Art. 21.2.f - Basic cyber hygiene practices",
        "severity_fail": Severity.MEDIUM,
        "remediation": "Enable SMB Signing (Message Integrity) to prevent Man-in-the-Middle attacks."
    },
    "connectivity": {
        "name": "Target Reachability",
        "article": "N/A - Operational Check",
        "severity_fail": Severity.INFO,
        "remediation": "Check network connectivity, firewall rules, and if the service is running."
    }
}
