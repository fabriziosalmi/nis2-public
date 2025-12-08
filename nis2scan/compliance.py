from dataclasses import dataclass, field
from typing import List, Dict, Any
from .scanner import ScanResult
from .summary import SummaryGenerator

@dataclass
class ComplianceFinding:
    severity: str  # HIGH, MEDIUM, LOW, INFO
    category: str # ENCRYPTION, EXPOSURE, RESILIENCE, ACCESS CONTROL
    message: str
    rationale: str
    target: str
    reference: str = "" # e.g. "D.Lgs 138/2024 Art. 21"
    
    # Report 2.0 Enhanced Fields
    cvss_base_score: float = 0.0
    cvss_vector: str = "" # e.g. "CVSS:3.1/AV:N/AC:L..."
    technical_detail: str = "" # Evidence like "TLS 1.1 enabled"
    remediation: str = "" # Actionable step
    remediation_cost: str = "Medium" # Low, Medium, High
    remediation_effort: str = "Medium" # Low, Medium, High
    compliance_article: str = "" # Mapping to specific Art 21 point

@dataclass
class ComplianceReport:
    total_score: int
    findings: List[ComplianceFinding] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=dict)
    checked_items: List[str] = field(default_factory=list)
    
    executive_summary: str = ""
    compliance_matrix: Dict[str, str] = field(default_factory=dict) # Art 21 items -> Status
    compliance_matrix: Dict[str, str] = field(default_factory=dict) # Art 21 items -> Status
    assets: List[Dict[str, Any]] = field(default_factory=list) # Inventory
    scan_id: str = "N/A" # Unique Scan ID

class ComplianceEngine:
    def __init__(self, config):
        self.config = config

    def evaluate(self, scan_results: List[ScanResult], scan_id: str = "N/A") -> ComplianceReport:
        all_findings = []
        stats = {
            'analyzed_hosts': 0, 
            'active_hosts': 0, 
            'compliant_hosts': 0, 
            'critical_risk_hosts': 0,
            'high_risk_hosts': 0, 
            'medium_risk_hosts': 0,
            'low_risk_hosts': 0
        }
        
        # Methodology Tracking for Report
        checked_items = [
            "Critical Port Exposure (DB, SMB, RDP, Telnet, FTP)",
            "TLS/SSL Configuration (Version, Expiry)",
            "HTTP Security Headers (HSTS)",
            "DNS Security (DNSSEC, AXFR)",
            "Secrets Detection (AWS Keys, Tokens, Private Keys)",
            "WHOIS Domain Expiry Monitoring",
            "WAF/CDN Protection Detection",
            "Italian Legal Compliance (P.IVA, Privacy, Cookies)"
        ]

        # NIS2 Art 21 Mapping Status (Default to Manual unless checked)
        # We will update these as we perform checks
        nis2_matrix = {
            "a) Risk Analysis per Information Security": "Manual Verification Required",
            "b) Incident Handling": "Manual Verification Required",
            "c) Business Continuity & Crisis Mgmt": "Manual Verification Required",
            "d) Supply Chain Security": "Partially Automated", # SSL/TLS
            "e) Security in Network & Information Systems": "Automated", # Vuln scan
            "f) Cyber Hygiene & Training": "Partially Automated", # Basic hygiene (Updates/Crypto)
            "g) Cryptography & Encryption": "Automated", # HTTPS/TLS
            "h) Human Resources Security": "Manual Verification Required",
            "i) Access Control & Asset Management": "Partially Automated", # Port exposure
            "j) MFA & Communications": "Manual Verification Required"
        }
        
        total_host_scores = 0
        
        for host in scan_results:
            stats['analyzed_hosts'] += 1
            
            # Skip inactive hosts for compliance scoring (but track them as analyzed)
            if not host.is_alive:
                continue

            stats['active_hosts'] += 1
            host_findings = []
            current_host_score = 100

            # 1. CRITICAL EXPOSURE
            critical_map = {
                445: "SMB (Server Message Block)",
                3389: "RDP (Remote Desktop)",
                3306: "MySQL Database",
                5432: "PostgreSQL Database",
                6379: "Redis Key-Value Store",
                27017: "MongoDB"
            }
            
            for port, name in critical_map.items():
                if port in host.open_ports:
                     f = ComplianceFinding(
                        severity="CRITICAL",
                        category="ACCESS CONTROL",
                        message=f"{name} Port ({port}) is EXPOSED",
                        rationale="Critical infrastructure services must not be exposed directly to the public internet.",
                        target=host.ip,
                        reference="D.Lgs 138/2024 Art. 21.2.i (Access Control)",
                        cvss_base_score=9.1,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        technical_detail=f"Port {port} is open and accepting connections from public IP.",
                        remediation="Block access to this port immediately via Firewall/ACL. Use VPN for administrative access.",
                        remediation_cost="Low",
                        remediation_effort="Low",
                        compliance_article="Art. 21.2.i (Access Control)"
                    )
                     host_findings.append(f)

            # 2. HIGH EXPOSURE
            if 23 in host.open_ports:
                f = ComplianceFinding(
                    severity="HIGH",
                    category="EXPOSURE",
                    message="Telnet Port (23) is OPEN",
                    rationale="Use of insecure legacy protocols exposing cleartext credentials.",
                    target=host.ip,
                    reference="D.Lgs 138/2024 Art. 21.2.g (Cryptography)",
                    cvss_base_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    technical_detail="Telnet service detected. Credential sniffing possible.",
                    remediation="Disable Telnet and replace with SSH. Ensure port 23 is closed.",
                    remediation_cost="Low",
                    remediation_effort="Medium",
                    compliance_article="Art. 21.2.g (Cryptography)"
                )
                host_findings.append(f)
            
            if 21 in host.open_ports:
                 f = ComplianceFinding(
                    severity="MEDIUM",
                    category="EXPOSURE",
                    message="FTP Port (21) is OPEN",
                    rationale="Legacy protocol usage should be minimized. Ensure FTPS is enforced.",
                    target=host.ip,
                    reference="D.Lgs 138/2024 Art. 21.2.g (Cryptography)",
                    cvss_base_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    technical_detail="Unencrypted FTP service reachable.",
                    remediation="Migrate to SFTP/SCP or enforce FTPS (TLS).",
                    remediation_cost="Medium",
                    remediation_effort="Medium",
                    compliance_article="Art. 21.2.g (Cryptography)"
                )
                 host_findings.append(f)

            # 3. ENCRYPTION
            for port, info in host.http_info.items():
                # Accuracy Fix: Check if HTTP service was actually reachable/valid
                status = info.get('status')
                if not status:
                    # Service didn't respond with HTTP status, so don't flag "Redirect" issues.
                    continue

                if port == 80:
                     if not any("https://" in r for r in info.get('redirects', [])):
                         f = ComplianceFinding(
                            severity="LOW",
                            category="ENCRYPTION",
                            message="Port 80 does not force redirect to HTTPS",
                            rationale="Data in transit must be encrypted.",
                            target=host.ip,
                            reference="D.Lgs 138/2024 Art. 21.2.g (Cryptography)",
                            cvss_base_score=3.1,
                            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            technical_detail="HTTP response code 200 OK on port 80 without redirect location.",
                            remediation="Configure web server to Redirect (301) all HTTP traffic to HTTPS.",
                            remediation_cost="Low",
                            remediation_effort="Low",
                            compliance_article="Art. 21.2.g (Cryptography)"
                         )
                         host_findings.append(f)
                
                missing = info.get('missing_headers', [])
                if 'Strict-Transport-Security' in missing and port in [443, 8443]:
                     f = ComplianceFinding(
                        severity="MEDIUM",
                        category="RESILIENCE",
                        message=f"HSTS Header missing on port {port}",
                        rationale="Prevents downgrade attacks to insecure protocols.",
                        target=host.ip,
                        reference="NIS2 Directive Art. 21.2.f (Cyber Hygiene)",
                        cvss_base_score=4.0,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                        technical_detail="Strict-Transport-Security header not returned by server.",
                        remediation="Enable HSTS headers (max-age=31536000; includeSubDomains).",
                        remediation_cost="Low",
                        remediation_effort="Low",
                        compliance_article="Art. 21.2.f (Cyber Hygiene)"
                     )
                     host_findings.append(f)
            
            # TLS
            for port, info in host.tls_info.items():
                version = info.get('version', '')
                if version in ['TLSv1', 'TLSv1.1']:
                    f = ComplianceFinding(
                        severity="HIGH",
                        category="ENCRYPTION",
                        message=f"Obsolete TLS Version ({version}) detected on port {port}",
                        rationale="Weak cryptography.",
                        target=host.ip,
                        reference="D.Lgs 138/2024 Art. 21.2.g (Cryptography)",
                        cvss_base_score=7.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        technical_detail=f"Server negotiated {version} which is deprecated.",
                        remediation="Disable support for TLS 1.0 and 1.1. Enforce TLS 1.2 or 1.3.",
                        remediation_cost="Medium",
                        remediation_effort="Medium",
                        compliance_article="Art. 21.2.g (Cryptography)"
                    )
                    host_findings.append(f)
                
                # Check for TLS Errors (e.g. Self-signed, Verify Failed)
                if info.get('error'):
                    f = ComplianceFinding(
                        severity="MEDIUM",
                        category="CRYPTO",
                        message=f"SSL/TLS Certificate Verification Failed on {port}",
                        rationale="Certificate is invalid, self-signed, or untrusted.",
                        target=host.ip,
                        reference="NIS2 Directive Art. 21.2.g (Cryptography)",
                        cvss_base_score=5.0,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                        technical_detail=f"TLS Error: {info.get('error')}",
                        remediation="Ensure a valid, trusted certificate is installed (e.g. Let's Encrypt).",
                        remediation_cost="Medium",
                        remediation_effort="Low",
                        compliance_article="Art. 21.2.g (Cryptography)"
                    )
                    host_findings.append(f)

                if info.get('expired'):
                    f = ComplianceFinding(
                        severity="HIGH",
                        category="CRYPTO",
                        message=f"SSL Certificate Expired on {port}",
                        rationale="Failure to maintain security infrastructure.",
                        target=host.ip,
                        reference="NIS2 Directive Art. 21.2.d (Supply Chain)",
                        cvss_base_score=7.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H",
                        technical_detail="Certificate date is past 'notAfter' field.",
                        remediation="Renew the SSL certificate immediately.",
                        remediation_cost="Medium",
                        remediation_effort="Low",
                        compliance_article="Art. 21.2.d (Supply Chain)"
                    )
                    host_findings.append(f)

            # DNS Checks
            if host.dns_info:
                if host.dns_info.get('zone_transfer_exposed'):
                    f = ComplianceFinding(
                        severity="CRITICAL",
                        category="EXPOSURE",
                        message="DNS Zone Transfer (AXFR) Allowed",
                        rationale="Public disclosure of entire DNS zone is a severe information leak.",
                        target=host.target,
                        reference="NIS2 Directive Art. 21.2.f (Network Security)",
                        cvss_base_score=9.0,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                        technical_detail="Nameserver allowed AXFR query resulting in full zone dump.",
                        remediation="Restrict AXFR (Zone Transfers) to trusted secondary nameservers only.",
                        remediation_cost="Low",
                        remediation_effort="Low",
                        compliance_article="Art. 21.2.e (Net Security)"
                    )
                    host_findings.append(f)
                
                if not host.dns_info.get('dnssec_enabled'):
                    f = ComplianceFinding(
                        severity="MEDIUM",
                        category="RESILIENCE",
                        message="DNSSEC Not Enabled",
                        rationale="Domain does not integrity-protect its records.",
                        target=host.ip,
                        reference="NIS2 Directive Art. 21.2.j (Hygiene)",
                        cvss_base_score=4.0,
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
                        technical_detail="DNSKEY record not found or valid chain not established.",
                        remediation="Enable and configure DNSSEC at your registrar and DNS provider.",
                        remediation_cost="Low",
                        remediation_effort="Medium",
                        compliance_article="Art. 21.2.f (Cyber Hygiene)"
                    )
                    host_findings.append(f)

                # Email Security (SPF/DMARC)
                spf_info = host.dns_info.get('spf', {})
                if not spf_info.get('present'):
                    f = ComplianceFinding(
                        severity="MEDIUM",
                        category="EMAIL SECURITY",
                        message="SPF Record Missing",
                        rationale="Lack of SPF allows attackers to spoof emails from your domain.",
                        target=host.target, # Domain level
                        reference="NIS2 Art. 21.2.j (Secured Communications)",
                        cvss_base_score=4.3,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                        technical_detail="No TXT record starting with 'v=spf1' found.",
                        remediation="Configure SPF record (e.g., 'v=spf1 mx -all') to authorize senders.",
                        remediation_cost="Low",
                        remediation_effort="Low",
                        compliance_article="Art. 21.2.j (Secured Communications)"
                    )
                    host_findings.append(f)

                dmarc_info = host.dns_info.get('dmarc', {})
                if not dmarc_info.get('present'):
                    f = ComplianceFinding(
                        severity="MEDIUM",
                        category="EMAIL SECURITY",
                        message="DMARC Record Missing",
                        rationale="DMARC is essential for email authentication and reporting spoofing attempts.",
                        target=host.target, # Domain level
                        reference="NIS2 Art. 21.2.j (Secured Communications)",
                        cvss_base_score=4.3,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                        technical_detail="No TXT record found at _dmarc subdomain.",
                        remediation="Implement DMARC policy (start with p=none for monitoring).",
                        remediation_cost="Low",
                        remediation_effort="Medium",
                        compliance_article="Art. 21.2.j (Secured Communications)"
                    )
                    host_findings.append(f)

            # ========== PHASE 5: ADVANCED CHECKS ==========
            
            # 1. Secrets Detection
            for port, http_data in host.http_info.items():
                if 'secrets' in http_data and http_data['secrets']:
                    for secret in http_data['secrets']:
                        f = ComplianceFinding(
                            severity="CRITICAL",
                            category="DATA PROTECTION",
                            message=f"Leaked Secret Detected: {secret['type']}",
                            rationale="Exposed credentials or API keys pose immediate security risk.",
                            target=f"{host.ip}:{port}",
                            reference="NIS2 Art. 21.2.g (Cryptography)",
                            cvss_base_score=9.8,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            technical_detail=f"Found {secret['type']} at position {secret['position']}",
                            remediation="Immediately rotate exposed credentials. Remove secrets from code/responses. Use environment variables or secret management systems.",
                            remediation_cost="High",
                            remediation_effort="High",
                            compliance_article="Art. 21.2.g (Cryptography & Encryption)"
                        )
                        host_findings.append(f)
            
            # 2. WHOIS Domain Expiry
            if host.whois_info.get('warning'):
                days_left = host.whois_info.get('days_remaining', 0)
                f = ComplianceFinding(
                    severity="HIGH",
                    category="BUSINESS CONTINUITY",
                    message=f"Domain Expiring Soon ({days_left} days)",
                    rationale="Domain expiration can cause service disruption and loss of control.",
                    target=host.ip,
                    reference="NIS2 Art. 21.2.c (Business Continuity)",
                    cvss_base_score=6.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
                    technical_detail=f"Domain expires: {host.whois_info.get('expiry_date', 'Unknown')}",
                    remediation="Renew domain registration immediately. Enable auto-renewal.",
                    remediation_cost="Low",
                    remediation_effort="Low",
                    compliance_article="Art. 21.2.c (Business Continuity)"
                )
                host_findings.append(f)
            
            # 3. WAF/CDN Protection (Positive finding - reduces risk)
            for port, http_data in host.http_info.items():
                if 'waf_cdn' in http_data and http_data['waf_cdn'].get('protected'):
                    # This is a POSITIVE finding - we note it but don't penalize
                    # We could add an INFO level finding or just track in stats
                    pass  # No penalty for having protection
            
            # 4. Italian Legal Compliance
            for port, http_data in host.http_info.items():
                if 'legal' in http_data:
                    legal = http_data['legal']
                    italian = legal.get('italian_compliance', {})
                    
                    # P.IVA check (for Italian sites)
                    if not italian.get('piva_found'):
                        f = ComplianceFinding(
                            severity="LOW",
                            category="LEGAL COMPLIANCE",
                            message="Italian P.IVA Not Found",
                            rationale="Italian companies must display VAT number (P.IVA) on their website.",
                            target=f"{host.ip}:{port}",
                            reference="Italian D.Lgs 138/2024",
                            cvss_base_score=0.0,
                            technical_detail="P.IVA pattern not detected in HTML",
                            remediation="Add P.IVA to website footer or legal notice section.",
                            remediation_cost="Low",
                            remediation_effort="Low",
                            compliance_article="Italian Legal Requirements"
                        )
                        host_findings.append(f)
                    
                    # Privacy Policy check
                    if not italian.get('privacy_policy_found'):
                        f = ComplianceFinding(
                            severity="MEDIUM",
                            category="LEGAL COMPLIANCE",
                            message="Privacy Policy Link Not Found",
                            rationale="GDPR and Italian law require accessible privacy policy.",
                            target=f"{host.ip}:{port}",
                            reference="GDPR Art. 13, D.Lgs 196/2003",
                            cvss_base_score=3.1,
                            technical_detail="Privacy policy keywords not detected",
                            remediation="Add visible Privacy Policy link to website.",
                            remediation_cost="Low",
                            remediation_effort="Low",
                            compliance_article="GDPR Compliance"
                        )
                        host_findings.append(f)
                    
                    # Cookie Banner check
                    cookie_banner = legal.get('cookie_banner', {})
                    if not cookie_banner.get('banner_detected'):
                        f = ComplianceFinding(
                            severity="MEDIUM",
                            category="LEGAL COMPLIANCE",
                            message="Cookie Consent Banner Not Detected",
                            rationale="GDPR requires explicit consent for non-essential cookies.",
                            target=f"{host.ip}:{port}",
                            reference="GDPR Art. 7, ePrivacy Directive",
                            cvss_base_score=3.1,
                            technical_detail="Cookie consent keywords not found",
                            remediation="Implement cookie consent banner (e.g., Cookiebot, OneTrust).",
                            remediation_cost="Medium",
                            remediation_effort="Medium",
                            compliance_article="GDPR Compliance"
                        )
                        host_findings.append(f)

                # Security.txt Check
                if http_data.get('security_txt_found'):
                    # Positive finding (optional to report, but good to track)
                    pass
                else:
                    # Only report if it's a main web port to avoid noise
                    if port in [80, 443]:
                        f = ComplianceFinding(
                            severity="LOW",
                            category="VULNERABILITY HANDLING",
                            message="Security.txt Missing",
                            rationale="A security.txt file helps security researchers report vulnerabilities safely.",
                            target=f"{host.ip}:{port}",
                            reference="RFC 9116, NIS2 Art. 21.2.e",
                            cvss_base_score=0.0,
                            technical_detail="File not found at /.well-known/security.txt or /security.txt",
                            remediation="Publish a security.txt file with contact details.",
                            remediation_cost="Low",
                            remediation_effort="Low",
                            compliance_article="Art. 21.2.e (Vulnerability Handling)"
                        )
                        host_findings.append(f)

            # 5. Obsolete Software & Information Disclosure (Passive)
            for port, http_data in host.http_info.items():
                # Check for Information Disclosure (Tech Stack)
                if 'tech_stack' in http_data and http_data['tech_stack']:
                    f = ComplianceFinding(
                        severity="LOW",
                        category="INFO DISCLOSURE",
                        message="Technology Stack Exposed",
                        rationale="Exposing detailed version information aids attackers in targeting specific vulnerabilities.",
                        target=f"{host.ip}:{port}",
                        reference="NIS2 Art. 21.2.e (Security in Acquisition)",
                        cvss_base_score=2.6,
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        technical_detail=f"Headers found: {', '.join(http_data['tech_stack'])}",
                        remediation="Configure web server to suppress 'X-Powered-By', 'X-AspNet-Version' and similar headers.",
                        remediation_cost="Low",
                        remediation_effort="Low",
                        compliance_article="Art. 21.2.e (Security in Acquisition)"
                    )
                    host_findings.append(f)

                # Check for Obsolete/Vulnerable Software (Basic Banner Matching)
                # This is a simplified check. In a real scenario, this would query a CVE database.
                server_header = http_data.get('headers', {}).get('Server', '').lower()
                
                # Example: Apache 2.2 (EOL 2017), PHP 5.x (EOL 2018), IIS 6.0 (EOL 2015)
                obsolete_signatures = [
                    ('apache/2.2', 'Apache 2.2 is EOL since 2017'),
                    ('apache/2.0', 'Apache 2.0 is EOL since 2013'),
                    ('nginx/1.0', 'Nginx 1.0 is severely outdated'),
                    ('php/5.', 'PHP 5.x is EOL since 2018'),
                    ('php/7.0', 'PHP 7.0 is EOL since 2019'),
                    ('microsoft-iis/6.0', 'IIS 6.0 is EOL since 2015'),
                    ('microsoft-iis/7.0', 'IIS 7.0 is EOL since 2020')
                ]

                for sig, reason in obsolete_signatures:
                    if sig in server_header or any(sig in ts.lower() for ts in http_data.get('tech_stack', [])):
                        f = ComplianceFinding(
                            severity="HIGH",
                            category="VULNERABILITY",
                            message="Obsolete/EOL Software Detected",
                            rationale="Using End-of-Life software guarantees unpatched vulnerabilities.",
                            target=f"{host.ip}:{port}",
                            reference="NIS2 Art. 21.2.e (Vulnerability Handling)",
                            cvss_base_score=9.8, # Assuming critical CVEs exist for EOL software
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            technical_detail=f"Banner matched: {reason} (Source: {server_header})",
                            remediation="Upgrade to a supported version immediately.",
                            remediation_cost="High",
                            remediation_effort="High",
                            compliance_article="Art. 21.2.e (Vulnerability Handling)"
                        )
                        host_findings.append(f)
                        break # Report once per host/port

            # Aggregate Host Stats
            if any(f.severity == 'CRITICAL' for f in host_findings):
                stats['critical_risk_hosts'] += 1
            elif any(f.severity == 'HIGH' for f in host_findings):
                stats['high_risk_hosts'] += 1
            elif any(f.severity == 'MEDIUM' for f in host_findings):
                stats['medium_risk_hosts'] += 1
            elif any(f.severity == 'LOW' for f in host_findings):
                stats['low_risk_hosts'] += 1
            elif not host_findings:
                stats['compliant_hosts'] += 1
            
            # Calculate Host Score
            for f in host_findings:
                if f.severity == 'CRITICAL': current_host_score -= 50
                if f.severity == 'HIGH': current_host_score -= 20
                if f.severity == 'MEDIUM': current_host_score -= 10
                if f.severity == 'LOW': current_host_score -= 5
            
            total_host_scores += max(0, current_host_score)
            all_findings.extend(host_findings)

        # Average Score Calculation
        if stats['active_hosts'] > 0:
            final_score = int(total_host_scores / stats['active_hosts'])
        else:
            final_score = 100 
        
        # Add 'DNS Security' to checked items
        if "DNS Security (DNSSEC, AXFR)" not in checked_items:
            checked_items.append("DNS Security (DNSSEC, AXFR)")

        # Compile Asset Inventory
        assets = []
        for host in scan_results:
            assets.append({
                "target": host.target,
                "ip": host.ip,
                "status": "Active" if host.is_alive else "Unresponsive",
                "os": "Unknown" if not host.os_match else host.os_match,
                "ports": sorted(host.open_ports)
            })

        # Generate Executive Summary using Modular Generator
        summary_gen = SummaryGenerator()
        exec_summary = summary_gen.generate(
            ComplianceReport(
                total_score=final_score,
                findings=all_findings,
                stats=stats,
                checked_items=checked_items,
                assets=assets,
                compliance_matrix=nis2_matrix,
                scan_id=scan_id
            )
        )

        return ComplianceReport(
            total_score=final_score,
            findings=all_findings,
            stats=stats,
            checked_items=checked_items,
            executive_summary=exec_summary,
            compliance_matrix=nis2_matrix,
            assets=assets,
            scan_id=scan_id
        )
