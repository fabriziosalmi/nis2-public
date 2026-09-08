# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from .scanner import ScanResult
from . import cvss
from .summary import SummaryGenerator

# Canonical NIS2 Art. 21(2) sub-paragraphs (a–j) — single source of truth for
# this package, mirroring packages/api/app/routers/governance.py SUBPARAGRAPHS.
# Findings/matrix below MUST use these letters: a regression where cryptography
# was tagged 21.2.g (should be h) and cyber hygiene 21.2.f (should be g) — and
# those wrong letters were persisted onto auditable Finding records — is the
# bug this guard + test_compliance_mapping.py exist to prevent recurring.
SUBPARAGRAPHS: Dict[str, str] = {
    "a": "Risk analysis and information system security policies",
    "b": "Incident handling",
    "c": "Business continuity, backup, disaster recovery, crisis management",
    "d": "Supply chain security",
    "e": "Security in network and information systems acquisition, development and maintenance",
    "f": "Policies and procedures to assess effectiveness of risk management measures",
    "g": "Basic cyber hygiene practices and cybersecurity training",
    "h": "Cryptography and, where appropriate, encryption",
    "i": "Human resources security, access control policies and asset management",
    "j": "MFA, secured voice/video/text communications and secured emergency communications",
}
assert set(SUBPARAGRAPHS) == set("abcdefghij"), "NIS2 Art. 21(2) letter set drifted"


@dataclass
class ComplianceFinding:
    severity: str  # HIGH, MEDIUM, LOW, INFO
    category: str # ENCRYPTION, EXPOSURE, RESILIENCE, ACCESS CONTROL
    message: str
    rationale: str
    target: str
    reference: str = "" # e.g. "D.Lgs 138/2024 Art. 21"

    # Report 2.0 Enhanced Fields
    #
    # `cvss_base_score` is DERIVED from `cvss_vector` in __post_init__ — any
    # value passed in is ignored. A CVSS base score is, by specification, a
    # function of its vector, so a hand-picked number is not a CVSS score.
    #
    # It mattered: of the 28 findings that declared one, exactly 7 agreed with
    # the vector printed beside them in the dossier. Nine contradicted it — an
    # expired certificate was labelled 7.5 where its own vector computes 8.2, an
    # open AXFR 9.0 where it computes 8.6 — and twelve carried a number with no
    # vector at all, including a 9.8 that would have required a confidentiality,
    # integrity AND availability impact for reading a file.
    #
    # Findings with no defensible vector now publish NO score. An empty cell an
    # auditor can ask about beats a number nobody can justify, and several of
    # these are not vulnerabilities at all: a missing P.IVA or cookie banner is
    # a GDPR / consumer-law matter with no CVSS meaning.
    cvss_base_score: Optional[float] = None
    cvss_vector: str = "" # e.g. "CVSS:3.1/AV:N/AC:L..."
    technical_detail: str = "" # Evidence like "TLS 1.1 enabled"
    remediation: str = "" # Actionable step
    remediation_cost: str = "Medium" # Low, Medium, High
    remediation_effort: str = "Medium" # Low, Medium, High
    compliance_article: str = "" # Mapping to specific Art 21 point

    def __post_init__(self) -> None:
        # Derive, never trust. One source of truth — the vector — is what stops
        # the two numbers drifting apart again.
        self.cvss_base_score = cvss.score_for(self.cvss_vector)

@dataclass
class ComplianceReport:
    # None when nothing was assessed. A score is a claim about a posture, and a
    # scan that reached no live host has observed no posture to make a claim
    # about — it used to return 100, which is the most reassuring number
    # available and the one least supported by evidence. An empty or damaged
    # config_snapshot yielded no targets, no host was probed, and the scan was
    # recorded as fully compliant.
    total_score: Optional[int]
    findings: List[ComplianceFinding] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=dict)
    checked_items: List[str] = field(default_factory=list)

    executive_summary: str = ""
    compliance_matrix: Dict[str, str] = field(default_factory=dict)  # Art 21 items -> Status
    assets: List[Dict[str, Any]] = field(default_factory=list)  # Inventory
    scan_id: str = "N/A" # Unique Scan ID
    # Why no score, when there is none. Read by the API to decide whether the
    # scan completed or failed, and by the report so the empty cell has a
    # caption instead of being mistaken for a rendering fault.
    not_assessed_reason: str = ""

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
        # Canonical NIS2 Art. 21(2) letters (a–j). Pre-fix, f–i were shifted by
        # one (cryptography tagged g instead of h, cyber hygiene f instead of g,
        # etc.) — both here and in the per-finding references below.
        # What the scanner can EVIDENCE, not what its checks are named after.
        #
        # The previous values were a marketing claim rendered as an audit
        # artefact. "d) Supply Chain Security: Partially Automated" rested on
        # checking the `integrity` attribute of external <script> tags — Art.
        # 21(2)(d) is about supplier assessment, contracts and monitoring, and an
        # SRI check is not a partial automation of that, it is a different
        # subject. "g) Cyber Hygiene & Training: Partially Automated" rested on
        # response headers; training has no observable HTTP surface at all.
        # "Automated", unqualified, claimed completeness for (e) and (h) that a
        # public-surface probe cannot have.
        #
        # The disclaimer in the README does not travel with the PDF. What lands
        # on an auditor's desk is this table, so it has to be able to answer
        # "on what evidence?" by itself. Every value below names its evidence or
        # says the control is out of scope for an external scan.
        nis2_matrix = {
            "a) Risk Analysis per Information Security": "Manual Verification Required",
            "b) Incident Handling": "Manual Verification Required",
            "c) Business Continuity & Crisis Mgmt": "Manual Verification Required",
            "d) Supply Chain Security": "Not Assessed by Scan (supplier controls are organisational)",
            "e) Security in Network & Information Systems": "Partially Automated (public exposure surface only)",
            "f) Effectiveness Assessment of Risk Measures": "Manual Verification Required",
            "g) Cyber Hygiene & Training": "Not Assessed by Scan (training has no external surface)",
            "h) Cryptography & Encryption": "Partially Automated (public TLS endpoints only)",
            "i) HR Security, Access Control & Asset Management": "Partially Automated (port exposure only)",
            "j) MFA & Communications": "Manual Verification Required"
        }

        total_host_scores = 0

        # Track positive indicators for matrix automation
        has_security_txt = False
        has_spf_dmarc = False

        for host in scan_results:
            stats['analyzed_hosts'] += 1

            # Skip inactive hosts for compliance scoring (but track them as analyzed)
            if not host.is_alive:
                continue

            # Check for Matrix Automation Indicators
            # 1. Security.txt (Incident Handling)
            for port, http_data in host.http_info.items():
                if http_data.get('security_txt_found'):
                    has_security_txt = True

            # 2. SPF/DMARC (Secure Communications)
            if host.dns_info.get('spf', {}).get('present') or host.dns_info.get('dmarc', {}).get('present'):
                has_spf_dmarc = True

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
                    reference="D.Lgs 138/2024 Art. 21.2.h (Cryptography)",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    technical_detail="Telnet service detected. Credential sniffing possible.",
                    remediation="Disable Telnet and replace with SSH. Ensure port 23 is closed.",
                    remediation_cost="Low",
                    remediation_effort="Medium",
                    compliance_article="Art. 21.2.h (Cryptography)"
                )
                host_findings.append(f)

            if 21 in host.open_ports:
                 f = ComplianceFinding(
                    severity="MEDIUM",
                    category="EXPOSURE",
                    message="FTP Port (21) is OPEN",
                    rationale="Legacy protocol usage should be minimized. Ensure FTPS is enforced.",
                    target=host.ip,
                    reference="D.Lgs 138/2024 Art. 21.2.h (Cryptography)",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    technical_detail="Unencrypted FTP service reachable.",
                    remediation="Migrate to SFTP/SCP or enforce FTPS (TLS).",
                    remediation_cost="Medium",
                    remediation_effort="Medium",
                    compliance_article="Art. 21.2.h (Cryptography)"
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
                            reference="D.Lgs 138/2024 Art. 21.2.h (Cryptography)",
                            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            technical_detail="HTTP response code 200 OK on port 80 without redirect location.",
                            remediation="Configure web server to Redirect (301) all HTTP traffic to HTTPS.",
                            remediation_cost="Low",
                            remediation_effort="Low",
                            compliance_article="Art. 21.2.h (Cryptography)"
                         )
                         host_findings.append(f)

                # Header QUALITY, from nis2scan.headers. The presence check below
                # stays for the missing-HSTS case, but these carry the findings a
                # presence check structurally cannot raise: a CSP that allows
                # 'unsafe-inline', a wildcard script source, max-age=1, or
                # max-age=0 (which instructs browsers to forget the policy) all
                # used to count as satisfied controls.
                for issue in info.get('header_issues', []):
                    # The plain "header absent" cases are already covered by the
                    # dedicated findings below and in the missing-headers list;
                    # emitting both would double-count them in the score.
                    if "not set" in issue['summary'] or "No Content-Security-Policy" in issue['summary']:
                        continue
                    f = ComplianceFinding(
                        severity=issue['severity'],
                        category="CYBER HYGIENE",
                        message=f"{issue['summary']} on port {port}",
                        rationale=(
                            "A security header that is present but permissive is not a "
                            "control; it reads as one in an audit."
                        ),
                        target=f"{host.ip}:{port}",
                        reference="NIS2 Art. 21.2.g (Cyber Hygiene)",
                        technical_detail=issue['detail'],
                        remediation="Tighten the header — see the technical detail.",
                        remediation_cost="Low",
                        remediation_effort="Low",
                        compliance_article="Art. 21.2.g (Cyber Hygiene)"
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
                        reference="NIS2 Directive Art. 21.2.g (Cyber Hygiene)",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                        technical_detail="Strict-Transport-Security header not returned by server.",
                        remediation="Enable HSTS headers (max-age=31536000; includeSubDomains).",
                        remediation_cost="Low",
                        remediation_effort="Low",
                        compliance_article="Art. 21.2.g (Cyber Hygiene)"
                     )
                     host_findings.append(f)

                # Cookie Security
                cookies = info.get('cookies_analysis', [])
                for c in cookies:
                    # Check Secure Flag (only relevant for HTTPS)
                    if port in [443, 8443] and not c.get('secure'):
                        f = ComplianceFinding(
                            severity="LOW",
                            category="CYBER HYGIENE",
                            message="Cookie Missing 'Secure' Flag",
                            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            rationale="Cookies without the Secure flag can be transmitted over unencrypted connections.",
                            target=f"{host.ip}:{port}",
                            reference="NIS2 Art. 21.2.g (Cyber Hygiene)",
                            technical_detail=f"Cookie: {c.get('name', '(unnamed)')}",
                            remediation="Set the 'Secure' flag for all sensitive cookies.",
                            remediation_cost="Low",
                            remediation_effort="Low",
                            compliance_article="Art. 21.2.g (Cyber Hygiene)"
                        )
                        host_findings.append(f)

                    # SameSite=None is sent on cross-site requests — weaker than
                    # omitting the attribute in browsers that default to Lax.
                    # Substring matching could not tell it from SameSite=Strict.
                    if c.get('samesite') == 'None':
                        f = ComplianceFinding(
                            severity="LOW",
                            category="CYBER HYGIENE",
                            message="Cookie sets SameSite=None",
                            rationale=(
                                "The cookie is attached to cross-site requests, which is "
                                "weaker than omitting the attribute in browsers defaulting "
                                "to Lax."
                            ),
                            target=f"{host.ip}:{port}",
                            reference="NIS2 Art. 21.2.g (Cyber Hygiene)",
                            technical_detail=f"Cookie: {c.get('name', '(unnamed)')}",
                            remediation="Use SameSite=Lax or Strict unless the cookie is genuinely needed cross-site.",
                            remediation_cost="Low",
                            remediation_effort="Low",
                            compliance_article="Art. 21.2.g (Cyber Hygiene)"
                        )
                        host_findings.append(f)

                    # Check HttpOnly Flag
                    if not c.get('httponly'):
                        f = ComplianceFinding(
                            severity="LOW",
                            category="CYBER HYGIENE",
                            message="Cookie Missing 'HttpOnly' Flag",
                            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
                            rationale="Cookies without HttpOnly are accessible to JavaScript, increasing XSS risk.",
                            target=f"{host.ip}:{port}",
                            reference="NIS2 Art. 21.2.g (Cyber Hygiene)",
                            technical_detail=f"Cookie: {c.get('name', '(unnamed)')}",
                            remediation="Set the 'HttpOnly' flag for session cookies.",
                            remediation_cost="Low",
                            remediation_effort="Low",
                            compliance_article="Art. 21.2.g (Cyber Hygiene)"
                        )
                        host_findings.append(f)

                # SRI Check
                sri_missing = info.get('sri_missing', [])
                if sri_missing:
                    # Limit to first few to avoid spam
                    for src in sri_missing[:3]:
                        f = ComplianceFinding(
                            severity="MEDIUM",
                            category="SUPPLY CHAIN SECURITY",
                            message="Subresource Integrity (SRI) Missing",
                            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
                            rationale="External scripts without SRI can be tampered with to inject malware.",
                            target=f"{host.ip}:{port}",
                            reference="NIS2 Art. 21.2.d (Supply Chain Security)",
                            technical_detail=f"Script: {src}",
                            remediation="Add 'integrity' and 'crossorigin' attributes to external script tags.",
                            remediation_cost="Low",
                            remediation_effort="Medium",
                            compliance_article="Art. 21.2.d (Supply Chain Security)"
                        )
                        host_findings.append(f)

            # TLS
            for port, info in host.tls_info.items():
                # Check Negotiated Version
                version = info.get('version', '')
                if version in ['TLSv1', 'TLSv1.1']:
                    f = ComplianceFinding(
                        severity="HIGH",
                        category="ENCRYPTION",
                        message=f"Obsolete TLS Version ({version}) Negotiated on port {port}",
                        rationale="Weak cryptography.",
                        target=host.ip,
                        reference="D.Lgs 138/2024 Art. 21.2.h (Cryptography)",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        technical_detail=f"Server negotiated {version} which is deprecated.",
                        remediation="Disable support for TLS 1.0 and 1.1. Enforce TLS 1.2 or 1.3.",
                        remediation_cost="Medium",
                        remediation_effort="Medium",
                        compliance_article="Art. 21.2.h (Cryptography)"
                    )
                    host_findings.append(f)

                # Check Supported Weak Versions (Active Probe)
                weak_versions = info.get('weak_versions', [])
                if weak_versions:
                    f = ComplianceFinding(
                        severity="HIGH",
                        category="ENCRYPTION",
                        message=f"Weak TLS Versions Supported ({', '.join(weak_versions)}) on port {port}",
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        rationale="Server supports obsolete protocols (TLS 1.0/1.1) allowing downgrade attacks.",
                        target=host.ip,
                        reference="NIS2 Art. 21.2.h (Cryptography)",
                        technical_detail=f"Accepted connection using: {', '.join(weak_versions)}",
                        remediation="Disable TLS 1.0 and TLS 1.1 in server configuration.",
                        remediation_cost="Medium",
                        remediation_effort="Low",
                        compliance_article="Art. 21.2.h (Cryptography)"
                    )
                    host_findings.append(f)

                # Check Weak Ciphers (Negotiated)
                cipher = info.get('cipher', '')
                weak_ciphers = ['RC4', '3DES', 'DES', 'NULL', 'EXPORT', 'MD5', 'anon']
                if any(w in cipher for w in weak_ciphers):
                    f = ComplianceFinding(
                        severity="MEDIUM",
                        category="ENCRYPTION",
                        message=f"Weak Cipher Suite Negotiated ({cipher}) on port {port}",
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        rationale="The server negotiated a cipher suite known to be weak.",
                        target=host.ip,
                        reference="NIS2 Art. 21.2.h (Cryptography)",
                        technical_detail=f"Cipher: {cipher}",
                        remediation="Reconfigure server to prioritize strong ciphers (AES-GCM, ChaCha20) and disable weak ones.",
                        remediation_cost="Medium",
                        remediation_effort="Low",
                        compliance_article="Art. 21.2.h (Cryptography)"
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
                        reference="NIS2 Directive Art. 21.2.h (Cryptography)",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                        technical_detail=f"TLS Error: {info.get('error')}",
                        remediation="Ensure a valid, trusted certificate is installed (e.g. Let's Encrypt).",
                        remediation_cost="Medium",
                        remediation_effort="Low",
                        compliance_article="Art. 21.2.h (Cryptography)"
                    )
                    host_findings.append(f)

                # Chain / hostname verification. The scanner previously connected
                # with CERT_OPTIONAL and check_hostname=False and reported the
                # outcome as `valid`, so "valid" meant "a handshake completed" —
                # it could not tell a trusted certificate from a self-signed one,
                # and with no SNI it was frequently reading a different site's
                # certificate altogether. Now the probe validates for real, so
                # these are the first TLS trust findings the scanner can support.
                if info.get('chain_valid') is False:
                    detail = info.get('chain_error') or 'chain verification failed'
                    if info.get('hostname_match') is False:
                        f = ComplianceFinding(
                            severity="HIGH",
                            category="ENCRYPTION",
                            message=f"TLS certificate does not match the hostname on port {port}",
                            rationale=(
                                "A certificate issued for a different name gives clients no "
                                "assurance they are talking to this service."
                            ),
                            target=host.ip,
                            reference="D.Lgs 138/2024 Art. 21.2.h (Cryptography)",
                            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            technical_detail=f"Verification (with SNI): {detail}",
                            remediation="Install a certificate whose SAN list covers this hostname.",
                            remediation_cost="Low",
                            remediation_effort="Low",
                            compliance_article="Art. 21.2.h (Cryptography)"
                        )
                    else:
                        f = ComplianceFinding(
                            severity="HIGH",
                            category="ENCRYPTION",
                            message=f"TLS certificate chain does not validate on port {port}",
                            rationale=(
                                "Clients cannot establish trust: the certificate is expired, "
                                "self-signed, or missing an intermediate."
                            ),
                            target=host.ip,
                            reference="D.Lgs 138/2024 Art. 21.2.h (Cryptography)",
                            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                            technical_detail=f"Verification (with SNI): {detail}",
                            remediation=(
                                "Renew or replace the certificate and serve the full "
                                "intermediate chain."
                            ),
                            remediation_cost="Medium",
                            remediation_effort="Low",
                            compliance_article="Art. 21.2.h (Cryptography)"
                        )
                    host_findings.append(f)

                # Say so when the check could not run, instead of leaving a
                # missing finding to be read as a clean result. On the shipped
                # bookworm image this probe was silently inert for every scan
                # ever run: OpenSSL's default security level refused TLS 1.0/1.1
                # client-side, the handshake died before reaching the target, and
                # `weak_versions` came back empty for every host.
                if info.get('weak_probe_supported') is False:
                    f = ComplianceFinding(
                        severity="INFO",
                        category="ENCRYPTION",
                        message=f"Obsolete-protocol probe unavailable on port {port}",
                        rationale=(
                            "This scanner's OpenSSL build refuses to negotiate TLS 1.0/1.1, "
                            "so their absence from this report is not evidence of absence."
                        ),
                        target=host.ip,
                        reference="Scanner limitation",
                        technical_detail=(
                            "TLS 1.0/1.1 client contexts could not be created even at "
                            "SECLEVEL=0. Verify with an external tool before relying on "
                            "this result."
                        ),
                        remediation="Run the scanner on an image whose OpenSSL permits the probe.",
                        remediation_cost="Low",
                        remediation_effort="Low",
                        compliance_article="Art. 21.2.h (Cryptography)"
                    )
                    host_findings.append(f)

                if info.get('expired'):
                    f = ComplianceFinding(
                        severity="HIGH",
                        category="CRYPTO",
                        message=f"SSL Certificate Expired on {port}",
                        rationale="Failure to maintain security infrastructure.",
                        target=host.ip,
                        reference="NIS2 Directive Art. 21.2.h (Cryptography)",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H",
                        technical_detail="Certificate date is past 'notAfter' field.",
                        remediation="Renew the SSL certificate immediately.",
                        remediation_cost="Medium",
                        remediation_effort="Low",
                        compliance_article="Art. 21.2.h (Cryptography)"
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
                        reference="NIS2 Directive Art. 21.2.e (Network Security)",
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
                        reference="NIS2 Directive Art. 21.2.e (Network Security)",
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
                        technical_detail=(
                            "Zone is signed (DNSKEY present) but the parent publishes no DS "
                            "record, so resolvers ignore the signatures and the zone is "
                            "unprotected — the most common DNSSEC misconfiguration."
                            if host.dns_info.get('dnssec_dnskey')
                            else "No DNSKEY record: the zone is not signed."
                        ),
                        remediation="Enable and configure DNSSEC at your registrar and DNS provider.",
                        remediation_cost="Low",
                        remediation_effort="Medium",
                        compliance_article="Art. 21.2.e (Network Security)"
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
                            rationale=(
                                "A credential is readable by anyone who requests the page. Scored "
                                "for the disclosure that was actually observed (C:H); the previous "
                                "9.8 additionally claimed integrity and availability impact, which "
                                "would require knowing what the key is authorised to do — the scan "
                                "cannot see that, and the true impact may be higher."
                            ),
                            target=f"{host.ip}:{port}",
                            reference="NIS2 Art. 21.2.h (Cryptography)",
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            technical_detail=f"Found {secret['type']} at position {secret['position']}",
                            remediation="Immediately rotate exposed credentials. Remove secrets from code/responses. Use environment variables or secret management systems.",
                            remediation_cost="High",
                            remediation_effort="High",
                            compliance_article="Art. 21.2.h (Cryptography & Encryption)"
                        )
                        host_findings.append(f)

            # 2. WHOIS Domain Expiry & Data Accuracy (Art. 28)
            if host.whois_info:
                # Expiry Check
                if host.whois_info.get('warning'):
                    days_left = host.whois_info.get('days_remaining', 0)
                    f = ComplianceFinding(
                        severity="HIGH",
                        category="BUSINESS CONTINUITY",
                        message=f"Domain Expiring Soon ({days_left} days)",
                        rationale="Domain expiration can cause service disruption and loss of control.",
                        target=host.ip,
                        reference="NIS2 Art. 21.2.c (Business Continuity)",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
                        technical_detail=f"Domain expires: {host.whois_info.get('expiry_date', 'Unknown')}",
                        remediation="Renew domain registration immediately. Enable auto-renewal.",
                        remediation_cost="Low",
                        remediation_effort="Low",
                        compliance_article="Art. 21.2.c (Business Continuity)"
                    )
                    host_findings.append(f)

                # Data Availability Check (Art. 28)
                # If we have WHOIS info but critical fields are missing/empty (beyond redaction)
                # This is a heuristic. If 'registrar' is missing, it's suspicious.
                if not host.whois_info.get('registrar') and not host.whois_info.get('org'):
                     f = ComplianceFinding(
                        severity="LOW",
                        category="DOMAIN DATA",
                        message="Incomplete Domain Registration Data",
                        rationale="Entities must ensure domain registration data is accurate and complete.",
                        target=host.ip,
                        reference="NIS2 Art. 28 (Domain Registration Data)",
                        technical_detail="Registrar or Organization field missing in WHOIS data.",
                        remediation="Verify domain registration details with your registrar.",
                        remediation_cost="Low",
                        remediation_effort="Low",
                        compliance_article="Art. 28 (Domain Data)"
                    )
                     host_findings.append(f)
            else:
                # WHOIS Lookup Failed or Empty
                pass # Already handled by scanner errors or just ignored

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
                    # A check that could not run is not a check that failed.
                    # The browser launch returns an explicit marker now; without
                    # this guard an empty result read as three confirmed
                    # violations against the scanned business.
                    if legal.get('unavailable'):
                        f = ComplianceFinding(
                            severity="INFO",
                            category="LEGAL COMPLIANCE",
                            message="Italian legal checks not assessed",
                            rationale=(
                                legal.get('unavailable_reason')
                                or "The legal checks could not be performed on this host."
                            ),
                            target=f"{host.ip}:{port}",
                            reference="NIS2 Art. 21.2.f (Effectiveness assessment)",
                            technical_detail="P.IVA, privacy policy and cookie banner were not evaluated.",
                            remediation="Install the headless browser on the scanner host and re-run the scan.",
                            remediation_cost="Low",
                            remediation_effort="Low",
                        )
                        host_findings.append(f)
                        continue
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
                            rationale="A security.txt file helps security researchers report vulnerabilities safely and supports incident reporting obligations.",
                            target=f"{host.ip}:{port}",
                            reference="RFC 9116, NIS2 Art. 21.2.e & Art. 23 (Reporting)",
                            technical_detail="File not found at /.well-known/security.txt or /security.txt",
                            remediation="Publish a security.txt file with contact details.",
                            remediation_cost="Low",
                            remediation_effort="Low",
                            compliance_article="Art. 21.2.e (Vulnerability Handling)"
                        )
                        host_findings.append(f)

                # Sensitive Files Check (Git/Env)
                if 'sensitive_files' in http_data and http_data['sensitive_files']:
                    for sfile in http_data['sensitive_files']:
                        f = ComplianceFinding(
                            severity="CRITICAL",
                            category="SUPPLY CHAIN SECURITY",
                            message=f"Sensitive File Exposed ({sfile})",
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            rationale="Exposed configuration or version control files can lead to full system compromise.",
                            target=f"{host.ip}:{port}",
                            reference="NIS2 Art. 21.2.d (Supply Chain Security)",
                            technical_detail=f"Found accessible {sfile}",
                            remediation=f"Immediately remove or deny access to {sfile}.",
                            remediation_cost="Low",
                            remediation_effort="Low",
                            compliance_article="Art. 21.2.d (Supply Chain Security)"
                        )
                        host_findings.append(f)

                # Server Header Information Leakage
                headers = http_data.get('headers', {})
                for h_name in ['Server', 'X-Powered-By']:
                    # Case insensitive lookup
                    h_val = next((v for k, v in headers.items() if k.lower() == h_name.lower()), None)
                    if h_val:
                        f = ComplianceFinding(
                            severity="LOW",
                            category="CYBER HYGIENE",
                            message=f"Information Leakage ({h_name})",
                            rationale="Revealing server versions helps attackers target specific vulnerabilities.",
                            target=f"{host.ip}:{port}",
                            reference="NIS2 Art. 21.2.g (Cyber Hygiene)",
                            technical_detail=f"Header {h_name}: {h_val}",
                            remediation="Configure server to suppress version banners.",
                            remediation_cost="Low",
                            remediation_effort="Low",
                            compliance_article="Art. 21.2.g (Cyber Hygiene)"
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
                            rationale=(
                                "End-of-life software receives no security patches. This is a "
                                "vulnerability-management failure, not an observed vulnerability: "
                                "no CVSS score is published because none can be computed. The "
                                "previous 9.8 was annotated in the source as 'assuming critical "
                                "CVEs exist' — CVSS scores a specific vulnerability, and a banner "
                                "match is not one. Banners are also spoofable and routinely stale "
                                "where a distribution backports fixes without changing the version "
                                "string, so the evidence here is the banner and nothing more."
                            ),
                            target=f"{host.ip}:{port}",
                            reference="NIS2 Art. 21.2.e (Vulnerability Handling)",
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
                if f.severity == 'CRITICAL':
                    current_host_score -= 50
                if f.severity == 'HIGH':
                    current_host_score -= 20
                if f.severity == 'MEDIUM':
                    current_host_score -= 10
                if f.severity == 'LOW':
                    current_host_score -= 5

            total_host_scores += max(0, current_host_score)
            all_findings.extend(host_findings)

        # Average Score Calculation
        # A score requires at least one host to have been assessed. The two
        # ways that fails are different and both used to score 100:
        #   analyzed_hosts == 0  the scan had no targets at all, which means
        #                        the stored configuration was empty or damaged
        #   active_hosts   == 0  targets existed and none answered
        # Neither is evidence of compliance.
        not_assessed_reason = ""
        if stats['active_hosts'] > 0:
            final_score = int(total_host_scores / stats['active_hosts'])
        elif stats['analyzed_hosts'] == 0:
            final_score = None
            not_assessed_reason = (
                "No targets were resolved for this scan, so nothing was assessed. "
                "Check the assets attached to it."
            )
        else:
            final_score = None
            not_assessed_reason = (
                f"{stats['analyzed_hosts']} target(s) were probed and none responded, "
                f"so nothing was assessed."
            )

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

        # Update NIS2 Matrix based on collected indicators
        if has_security_txt:
            nis2_matrix["b) Incident Handling"] = (
                "Partially Automated (security.txt published — a disclosure contact, "
                "not an incident-handling process)"
            )

        if has_spf_dmarc:
            nis2_matrix["j) MFA & Communications"] = (
                "Partially Automated (SPF/DMARC present — email authenticity only; "
                "MFA is not externally observable)"
            )

        # I3: an MX-record count is NOT evidence of business continuity / backup
        # / DR / crisis management, so Art. 21.2.c stays "Manual Verification
        # Required" rather than being inferred from DNS redundancy.

        # I5: neither of these upgrades survives the question "on what evidence?".
        #
        # Header and info-leakage checks were promoting (g) Cyber Hygiene &
        # TRAINING to partially automated. Training is people; it leaves no trace
        # in an HTTP response, and the scanner cannot speak to it at all.
        #
        # Secrets and exposed .env files were promoting (d) Supply Chain
        # Security. Finding a leaked credential on a host says nothing about how
        # that organisation assesses, contracts with or monitors its suppliers,
        # which is what Art. 21(2)(d) requires. Those findings are reported on
        # their own merits under (e) and (i); inflating an unrelated
        # sub-paragraph is how a compliance report stops being evidence.
        #
        # Both therefore stay as declared above. Do not re-add these lines
        # without evidence that actually bears on the sub-paragraph.

        # Generate Executive Summary using Modular Generator
        summary_gen = SummaryGenerator()
        exec_summary = summary_gen.generate(
            ComplianceReport(
                total_score=final_score,
                not_assessed_reason=not_assessed_reason,
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
            not_assessed_reason=not_assessed_reason,
            findings=all_findings,
            stats=stats,
            checked_items=checked_items,
            executive_summary=exec_summary,
            compliance_matrix=nis2_matrix,
            assets=assets,
            scan_id=scan_id
        )
