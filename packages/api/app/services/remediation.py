# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
NIS2 Remediation Playbooks & Effort Estimator.

Provides structured, copy-pasteable fix instructions per finding category.
Includes server-specific configs (Nginx, Apache, Caddy, IIS) and effort/cost estimation.
"""

from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Playbook Registry
# ---------------------------------------------------------------------------

PLAYBOOKS: Dict[str, Dict[str, Any]] = {
    # ── TLS / Certificates ──────────────────────────────────────────────
    "tls_obsolete_protocol": {
        "title": "Disable Obsolete TLS Protocols",
        "category": "ENCRYPTION",
        "nis2_article": "Art. 21.2.g",
        "effort": "Low",
        "cost": "Free",
        "time_minutes": 30,
        "risk_if_ignored": "Man-in-the-middle attacks via protocol downgrade (POODLE, BEAST)",
        "steps": [
            "Identify which protocols are currently enabled",
            "Update server configuration to disable TLS 1.0 and 1.1",
            "Test with: openssl s_client -connect domain:443 -tls1",
            "Verify with SSL Labs: https://www.ssllabs.com/ssltest/",
        ],
        "configs": {
            "nginx": "ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;\nssl_prefer_server_ciphers off;",
            "apache": "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\nSSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256\nSSLHonorCipherOrder off",
            "caddy": "tls {\n    protocols tls1.2 tls1.3\n}",
            "iis": "# Run in PowerShell as Admin:\nDisable-TlsCipherSuite -Name TLS_RSA_WITH_AES_128_CBC_SHA\n# Or use IISCrypto tool: https://www.nartac.com/Products/IISCrypto",
        },
    },
    "tls_expired_cert": {
        "title": "Renew Expired TLS Certificate",
        "category": "ENCRYPTION",
        "nis2_article": "Art. 21.2.g",
        "effort": "Low",
        "cost": "Free (Let's Encrypt) / $50-500 (Commercial)",
        "time_minutes": 15,
        "risk_if_ignored": "Browser warnings drive away users, MITM possible",
        "steps": [
            "Check current certificate status: openssl s_client -connect domain:443 | openssl x509 -noout -dates",
            "Renew with certbot or your CA portal",
            "Install new certificate and restart web server",
            "Set up auto-renewal cron job",
        ],
        "configs": {
            "certbot": "# Renew immediately\ncertbot renew --force-renewal\n\n# Auto-renewal cron (add to crontab -e)\n0 0 1 * * certbot renew --quiet --post-hook 'systemctl reload nginx'",
            "acme_sh": "acme.sh --renew -d example.com --force\n\n# Auto-deploy\nacme.sh --install-cert -d example.com \\\n  --key-file /etc/ssl/private/key.pem \\\n  --fullchain-file /etc/ssl/certs/fullchain.pem \\\n  --reloadcmd 'systemctl reload nginx'",
        },
    },
    "tls_weak_key": {
        "title": "Upgrade Weak Cryptographic Key",
        "category": "ENCRYPTION",
        "nis2_article": "Art. 21.2.g",
        "effort": "Medium",
        "cost": "Free",
        "time_minutes": 60,
        "risk_if_ignored": "Key could be factored with modern hardware",
        "steps": [
            "Generate new key: openssl genrsa -out key.pem 4096",
            "Or use ECDSA: openssl ecparam -genkey -name prime256v1 -out key.pem",
            "Generate new CSR with the new key",
            "Submit CSR to your CA and install new certificate",
        ],
        "configs": {
            "openssl_rsa": "# Generate 4096-bit RSA key\nopenssl genrsa -out /etc/ssl/private/domain.key 4096\n\n# Generate CSR\nopenssl req -new -key /etc/ssl/private/domain.key -out domain.csr",
            "openssl_ecdsa": "# Generate ECDSA P-256 key (recommended)\nopenssl ecparam -genkey -name prime256v1 -noout -out /etc/ssl/private/domain.key\n\n# Generate CSR\nopenssl req -new -key /etc/ssl/private/domain.key -out domain.csr",
        },
    },
    "tls_self_signed": {
        "title": "Replace Self-Signed Certificate",
        "category": "ENCRYPTION",
        "nis2_article": "Art. 21.2.g",
        "effort": "Low",
        "cost": "Free (Let's Encrypt)",
        "time_minutes": 20,
        "risk_if_ignored": "Browsers reject self-signed certs, no chain of trust",
        "steps": [
            "Install certbot: apt install certbot python3-certbot-nginx",
            "Run: certbot --nginx -d yourdomain.com",
            "Verify: curl -I https://yourdomain.com",
        ],
        "configs": {
            "certbot_nginx": "certbot --nginx -d example.com -d www.example.com --non-interactive --agree-tos -m admin@example.com",
            "certbot_apache": "certbot --apache -d example.com -d www.example.com --non-interactive --agree-tos -m admin@example.com",
        },
    },
    # ── DNS Security ────────────────────────────────────────────────────
    "dns_no_spf": {
        "title": "Configure SPF Record",
        "category": "DNS_SECURITY",
        "nis2_article": "Art. 21.2.e",
        "effort": "Low",
        "cost": "Free",
        "time_minutes": 15,
        "risk_if_ignored": "Domain spoofing, phishing emails sent as your domain",
        "steps": [
            "Identify all legitimate mail sources (mail server, marketing tools, etc.)",
            "Create TXT record in your DNS zone",
            "Test with: dig TXT yourdomain.com",
            "Verify at: https://mxtoolbox.com/spf.aspx",
        ],
        "configs": {
            "dns_record": '# Basic SPF (adjust to your mail sources)\nyordomain.com. IN TXT "v=spf1 mx a include:_spf.google.com ~all"\n\n# Strict SPF (recommended)\nyourdomain.com. IN TXT "v=spf1 mx include:_spf.google.com -all"',
        },
    },
    "dns_no_dmarc": {
        "title": "Configure DMARC Record",
        "category": "DNS_SECURITY",
        "nis2_article": "Art. 21.2.e",
        "effort": "Low",
        "cost": "Free",
        "time_minutes": 15,
        "risk_if_ignored": "No visibility into email spoofing attempts",
        "steps": [
            "Ensure SPF and DKIM are configured first",
            "Start with p=none to monitor, then escalate to quarantine/reject",
            "Set up a DMARC report receiver (free: dmarcian.com, postmarkapp.com)",
        ],
        "configs": {
            "dns_record": '# Phase 1: Monitor only\n_dmarc.yourdomain.com. IN TXT "v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com; fo=1"\n\n# Phase 2: Quarantine (after monitoring)\n_dmarc.yourdomain.com. IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com; pct=100"\n\n# Phase 3: Reject (full enforcement)\n_dmarc.yourdomain.com. IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com; pct=100"',
        },
    },
    "dns_no_dkim": {
        "title": "Configure DKIM Signing",
        "category": "DNS_SECURITY",
        "nis2_article": "Art. 21.2.e",
        "effort": "Medium",
        "cost": "Free",
        "time_minutes": 45,
        "risk_if_ignored": "Email integrity cannot be verified, DMARC alignment fails",
        "steps": [
            "Generate DKIM key pair on your mail server",
            "Publish public key as DNS TXT record",
            "Configure mail server to sign outgoing mail",
            "Test with: https://dkimvalidator.com/",
        ],
        "configs": {
            "opendkim": '# Generate key\nopendkim-genkey -s mail -d yourdomain.com -b 2048\n\n# DNS record (from mail.txt):\nmail._domainkey.yourdomain.com. IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBg..."',
        },
    },
    # ── Exposed Services ────────────────────────────────────────────────
    "port_smb_exposed": {
        "title": "Block SMB (Port 445) From Internet",
        "category": "EXPOSURE",
        "nis2_article": "Art. 21.2.e",
        "effort": "Low",
        "cost": "Free",
        "time_minutes": 15,
        "risk_if_ignored": "WannaCry/EternalBlue exploitation, lateral movement",
        "steps": [
            "Block port 445 at the firewall level immediately",
            "Verify with: nmap -p 445 your-public-ip",
            "If SMB is needed internally, use VPN access only",
        ],
        "configs": {
            "iptables": "# Block SMB from external\niptables -A INPUT -p tcp --dport 445 -j DROP\niptables -A INPUT -p udp --dport 445 -j DROP\n\n# Save rules\niptables-save > /etc/iptables/rules.v4",
            "ufw": "ufw deny 445/tcp\nufw deny 445/udp\nufw reload",
            "aws_sg": "# AWS CLI — remove SMB from security group\naws ec2 revoke-security-group-ingress \\\n  --group-id sg-XXXXX \\\n  --protocol tcp --port 445 \\\n  --cidr 0.0.0.0/0",
        },
    },
    "port_rdp_exposed": {
        "title": "Secure RDP (Port 3389)",
        "category": "EXPOSURE",
        "nis2_article": "Art. 21.2.j",
        "effort": "Medium",
        "cost": "Free",
        "time_minutes": 60,
        "risk_if_ignored": "Brute-force attacks, ransomware entry vector #1",
        "steps": [
            "Block port 3389 from internet",
            "If remote access is needed, use VPN or Azure Bastion",
            "Enable NLA (Network Level Authentication)",
            "Enforce MFA on all RDP sessions",
        ],
        "configs": {
            "ufw": "ufw deny 3389/tcp\nufw reload",
            "iptables": "iptables -A INPUT -p tcp --dport 3389 -j DROP\niptables-save > /etc/iptables/rules.v4",
        },
    },
    "port_telnet_exposed": {
        "title": "Disable Telnet, Use SSH",
        "category": "EXPOSURE",
        "nis2_article": "Art. 21.2.j",
        "effort": "Low",
        "cost": "Free",
        "time_minutes": 20,
        "risk_if_ignored": "Credentials transmitted in plaintext",
        "steps": [
            "Disable telnet service: systemctl disable telnet.socket && systemctl stop telnet.socket",
            "Block port 23 at firewall",
            "Ensure SSH is properly configured with key-based auth",
        ],
        "configs": {
            "systemd": "systemctl disable telnet.socket\nsystemctl stop telnet.socket\nsystemctl mask telnet.socket",
            "ufw": "ufw deny 23/tcp\nufw reload",
        },
    },
    "port_db_exposed": {
        "title": "Block Database Ports From Internet",
        "category": "EXPOSURE",
        "nis2_article": "Art. 21.2.e",
        "effort": "Low",
        "cost": "Free",
        "time_minutes": 15,
        "risk_if_ignored": "Direct database access, data exfiltration",
        "steps": [
            "Block ports 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis), 27017 (MongoDB)",
            "Configure database to listen on localhost or private network only",
            "Use SSH tunnels or VPN for remote administration",
        ],
        "configs": {
            "ufw": "ufw deny 3306/tcp  # MySQL\nufw deny 5432/tcp  # PostgreSQL\nufw deny 6379/tcp  # Redis\nufw deny 27017/tcp # MongoDB\nufw reload",
            "postgres_conf": "# In postgresql.conf:\nlisten_addresses = 'localhost'\n\n# In pg_hba.conf — remove any 0.0.0.0/0 entries:\n# host all all 127.0.0.1/32 scram-sha-256",
        },
    },
    # ── HTTP Security Headers ───────────────────────────────────────────
    "header_missing_hsts": {
        "title": "Enable HSTS Header",
        "category": "WEB_SECURITY",
        "nis2_article": "Art. 21.2.g",
        "effort": "Low",
        "cost": "Free",
        "time_minutes": 10,
        "risk_if_ignored": "SSL stripping attacks",
        "steps": [
            "Add Strict-Transport-Security header",
            "Start with a short max-age, then increase to 1 year",
            "Consider adding to HSTS preload list",
        ],
        "configs": {
            "nginx": 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
            "apache": 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
            "caddy": 'header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
        },
    },
    "header_missing_csp": {
        "title": "Configure Content Security Policy",
        "category": "WEB_SECURITY",
        "nis2_article": "Art. 21.2.e",
        "effort": "Medium",
        "cost": "Free",
        "time_minutes": 120,
        "risk_if_ignored": "XSS attacks, data injection",
        "steps": [
            "Start with Content-Security-Policy-Report-Only to identify violations",
            "Audit all scripts, styles, and resources on your pages",
            "Build a strict policy, test thoroughly",
            "Switch to enforcement mode",
        ],
        "configs": {
            "nginx": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'\" always;",
            "apache": "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'\"",
        },
    },
    # ── Sensitive Files ─────────────────────────────────────────────────
    "sensitive_git_exposed": {
        "title": "Block .git Directory Access",
        "category": "DATA_LEAK",
        "nis2_article": "Art. 21.2.e",
        "effort": "Low",
        "cost": "Free",
        "time_minutes": 10,
        "risk_if_ignored": "Full source code disclosure, credential leaks",
        "steps": [
            "Block access to .git in web server config",
            "Remove .git from production deployments",
        ],
        "configs": {
            "nginx": "location ~ /\\.git {\n    deny all;\n    return 404;\n}",
            "apache": '<DirectoryMatch "^\\.git">\n    Require all denied\n</DirectoryMatch>',
            "caddy": "@git path /.git/*\nrespond @git 404",
        },
    },
    "sensitive_env_exposed": {
        "title": "Block .env File Access",
        "category": "DATA_LEAK",
        "nis2_article": "Art. 21.2.e",
        "effort": "Low",
        "cost": "Free",
        "time_minutes": 5,
        "risk_if_ignored": "Database credentials, API keys, secrets exposed",
        "steps": [
            "Block access to .env in web server config",
            "Move secrets to environment variables or a secrets manager",
        ],
        "configs": {
            "nginx": "location ~ /\\.env {\n    deny all;\n    return 404;\n}",
            "apache": '<Files ".env">\n    Require all denied\n</Files>',
        },
    },
}


# ---------------------------------------------------------------------------
# Lookup API
# ---------------------------------------------------------------------------


def get_playbook(
    finding_category: str, finding_message: str
) -> Optional[Dict[str, Any]]:
    """Find the best matching playbook for a finding."""
    msg_lower = finding_message.lower()

    # Direct mapping by keywords
    keyword_map = {
        "tls 1.0": "tls_obsolete_protocol",
        "tls 1.1": "tls_obsolete_protocol",
        "obsolete tls": "tls_obsolete_protocol",
        "expired": "tls_expired_cert",
        "weak key": "tls_weak_key",
        "self-signed": "tls_self_signed",
        "spf": "dns_no_spf",
        "dmarc": "dns_no_dmarc",
        "dkim": "dns_no_dkim",
        "445": "port_smb_exposed",
        "smb": "port_smb_exposed",
        "3389": "port_rdp_exposed",
        "rdp": "port_rdp_exposed",
        "telnet": "port_telnet_exposed",
        "port 23": "port_telnet_exposed",
        "3306": "port_db_exposed",
        "5432": "port_db_exposed",
        "6379": "port_db_exposed",
        "27017": "port_db_exposed",
        "mysql": "port_db_exposed",
        "redis": "port_db_exposed",
        "mongodb": "port_db_exposed",
        "hsts": "header_missing_hsts",
        "strict-transport": "header_missing_hsts",
        "content-security": "header_missing_csp",
        "csp": "header_missing_csp",
        ".git": "sensitive_git_exposed",
        ".env": "sensitive_env_exposed",
    }

    for keyword, playbook_id in keyword_map.items():
        if keyword in msg_lower:
            return PLAYBOOKS.get(playbook_id)

    return None


def get_all_playbooks() -> Dict[str, Dict[str, Any]]:
    """Return all playbooks."""
    return PLAYBOOKS


# ---------------------------------------------------------------------------
# Effort Estimator
# ---------------------------------------------------------------------------

EFFORT_MATRIX = {
    "Low": {"hours": 0.5, "cost_eur_min": 0, "cost_eur_max": 200},
    "Medium": {"hours": 2, "cost_eur_min": 200, "cost_eur_max": 800},
    "High": {"hours": 8, "cost_eur_min": 800, "cost_eur_max": 3000},
}


def estimate_remediation(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate total remediation effort and cost estimate."""
    total_hours = 0
    total_cost_min = 0
    total_cost_max = 0
    breakdown = []

    for f in findings:
        playbook = get_playbook(f.get("category", ""), f.get("message", ""))
        effort = f.get("remediation_effort", "Medium")
        matrix = EFFORT_MATRIX.get(effort, EFFORT_MATRIX["Medium"])

        item = {
            "finding": f.get("message", "Unknown"),
            "severity": f.get("severity", "MEDIUM"),
            "effort": effort,
            "hours": matrix["hours"],
            "cost_range": f"€{matrix['cost_eur_min']}-{matrix['cost_eur_max']}",
            "playbook_available": playbook is not None,
        }
        if playbook:
            item["playbook_title"] = playbook["title"]
            item["time_minutes"] = playbook["time_minutes"]
            item["hours"] = playbook["time_minutes"] / 60

        breakdown.append(item)
        total_hours += item["hours"]
        total_cost_min += matrix["cost_eur_min"]
        total_cost_max += matrix["cost_eur_max"]

    return {
        "total_findings": len(findings),
        "total_hours": round(total_hours, 1),
        "total_cost_estimate": f"€{total_cost_min:,}-{total_cost_max:,}",
        "cost_min_eur": total_cost_min,
        "cost_max_eur": total_cost_max,
        "breakdown": breakdown,
        "note": "Estimates based on standard remediation effort. Actual costs depend on infrastructure complexity.",
    }
