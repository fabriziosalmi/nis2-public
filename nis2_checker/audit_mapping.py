from nis2_checker.models import Severity

AUDIT_MAPPING = {
    # Existing Checks
    "ssl_tls": {
        "name": "Data Encryption (SSL/TLS)",
        "article": "Art. 21.2.h (Cryptography)",
        "severity_fail": Severity.CRITICAL,
        "remediation": "Enable HTTPS with TLS 1.2+."
    },
    "security_headers": {
        "name": "Security Headers",
        "article": "Art. 21.2.f (Cyber Hygiene)",
        "severity_fail": Severity.MEDIUM,
        "remediation": "Configure missing headers (HSTS, CSP, X-Frame-Options)."
    },
    # Nmap Checks
    "ssh_password_auth": {
        "name": "SSH Security",
        "article": "Art. 21.2.j (Multi-factor Auth)",
        "severity_fail": Severity.CRITICAL,
        "remediation": "Disable password auth, use SSH keys."
    },
    "deprecated_tls": {
        "name": "Legacy TLS Versions",
        "article": "Art. 21.2.h (Cryptography)",
        "severity_fail": Severity.HIGH,
        "remediation": "Disable TLS 1.0/1.1."
    },
    # New Strategic Checks
    "domain_expiry": {
        "name": "Domain Continuity (WHOIS)",
        "article": "Art. 21.2.c (Business Continuity)",
        "severity_fail": Severity.CRITICAL,
        "remediation": "Renew domain immediately. Enable auto-renew."
    },
    "secrets_leak": {
        "name": "Secrets Detection",
        "article": "Art. 21.2.h (Data Security)",
        "severity_fail": Severity.CRITICAL,
        "remediation": "Revoke leaked keys immediately and rotate credentials."
    },
    "tech_stack": {
        "name": "Supply Chain Security (Tech Stack)",
        "article": "Art. 21.2.d (Supply Chain)",
        "severity_fail": Severity.HIGH,
        "remediation": "Update obsolete software (e.g., PHP, Nginx, jQuery)."
    },
    "spf_record": {
        "name": "Email Security (SPF)",
        "article": "Art. 21.2.f (Cyber Hygiene)",
        "severity_fail": Severity.MEDIUM,
        "remediation": "Configure SPF record for the domain."
    },
    "dmarc_record": {
        "name": "Email Security (DMARC)",
        "article": "Art. 21.2.f (Cyber Hygiene)",
        "severity_fail": Severity.MEDIUM,
        "remediation": "Configure DMARC record for the domain."
    },
    "dnssec": {
        "name": "DNS Integrity (DNSSEC)",
        "article": "Art. 21.2.h (Cryptography)",
        "severity_fail": Severity.MEDIUM,
        "remediation": "Enable DNSSEC at your registrar/DNS provider."
    },
    "evidence_collected": {
        "name": "Visual Evidence",
        "article": "Audit Trail",
        "severity_fail": Severity.INFO,
        "remediation": "None"
    }
}
