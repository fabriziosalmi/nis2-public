from typing import List, Dict, Any
from dataclasses import dataclass

@dataclass
class BusinessRisk:
    name: str
    impact: str
    probability: str
    related_findings: List[Any]

class SummaryGenerator:
    """
    Generates a data-driven, business-focused executive summary for the NIS2 report.
    Output is HTML formatted for direct injection into the report template.
    """

    def generate(self, report) -> str:
        """
        Main entry point to generate the HTML summary.
        :param report: ComplianceReport object (duck-typed)
        :return: HTML string
        """
        risks = self._assess_business_impact(report.findings)
        metrics = self._calculate_metrics(report)
        action_plan = self._generate_action_plan(report.findings)
        
        return self._build_html(report, risks, metrics, action_plan)

    def _assess_business_impact(self, findings: List[Any]) -> List[BusinessRisk]:
        """Identify high-level business risks based on technical findings."""
        risks = []
        
        # 1. Secrets & Credential Theft (Critical)
        secrets_findings = [f for f in findings if "Secret" in f.message or "Credential" in f.message]
        if secrets_findings:
            risks.append(BusinessRisk(
                name="Credential Theft & Data Breach",
                impact="CRITICAL. Exposed API keys or secrets allow immediate unauthorized access to sensitive data and infrastructure.",
                probability="Certain",
                related_findings=secrets_findings
            ))

        # 2. Ransomware Risk (SMB/RDP/EOL)
        ransomware_findings = [f for f in findings if "SMB" in f.message or "RDP" in f.message or "Obsolete" in f.message]
        if ransomware_findings:
            risks.append(BusinessRisk(
                name="Ransomware & Lateral Movement",
                impact="High. Exposed administrative ports or EOL software provide easy entry points for ransomware deployment.",
                probability="High",
                related_findings=ransomware_findings
            ))

        # 3. Business Continuity (Domain Expiry)
        continuity_findings = [f for f in findings if "Domain Expiring" in f.message]
        if continuity_findings:
            risks.append(BusinessRisk(
                name="Service Interruption",
                impact="High. Imminent domain expiration will cause total service outage and potential loss of domain ownership.",
                probability="High",
                related_findings=continuity_findings
            ))

        # 4. Brand Reputation & Phishing (Email Security)
        email_findings = [f for f in findings if "SPF" in f.message or "DMARC" in f.message]
        if email_findings:
            risks.append(BusinessRisk(
                name="Brand Impersonation & Phishing",
                impact="Medium. Lack of email authentication (SPF/DMARC) allows attackers to spoof your domain, damaging reputation.",
                probability="Medium",
                related_findings=email_findings
            ))

        # 5. Data Leakage (Zone Transfer, Databases)
        leak_findings = [f for f in findings if "Zone Transfer" in f.message or "Database" in f.message or "FTP" in f.message or "Telnet" in f.message]
        if leak_findings:
            risks.append(BusinessRisk(
                name="Data Leakage & Espionage",
                impact="High. Unprotected data stores or legacy protocols allow unauthorized access to sensitive intellectual property.",
                probability="Medium",
                related_findings=leak_findings
            ))

        # 6. Legal & Compliance (GDPR/NIS2)
        legal_findings = [f for f in findings if "Privacy" in f.message or "Cookie" in f.message or "P.IVA" in f.message]
        if legal_findings:
            risks.append(BusinessRisk(
                name="Regulatory Fines (GDPR/NIS2)",
                impact="Medium. Non-compliance with transparency requirements (Privacy Policy, Cookies) exposes the organization to administrative fines.",
                probability="Medium",
                related_findings=legal_findings
            ))

        # 7. Supply Chain / Integrity (DNSSEC, SSL)
        integrity_findings = [f for f in findings if "DNSSEC" in f.message or "SSL" in f.message or "TLS" in f.message]
        if integrity_findings:
            risks.append(BusinessRisk(
                name="Supply Chain & Trust Integrity",
                impact="Medium. Weak cryptographic standards may allow man-in-the-middle attacks, undermining customer trust.",
                probability="Medium",
                related_findings=integrity_findings
            ))
            
        return risks

    def _calculate_metrics(self, report) -> Dict[str, Any]:
        """Generate quantitative metrics for the summary."""
        total_findings = len(report.findings)
        critical_count = sum(1 for f in report.findings if f.severity == 'CRITICAL')
        high_count = sum(1 for f in report.findings if f.severity == 'HIGH')
        
        # Calculate % of assets with critical issues
        # (Simplified assumption: findings map 1:1 to vulnerability instances)
        
        return {
            "total_findings": total_findings,
            "critical_count": critical_count,
            "high_count": high_count,
            "score": report.total_score,
            "status": "CRITICAL" if report.total_score < 50 else ("IMPROVEMENT NEEDED" if report.total_score < 80 else "GOOD")
        }

    def _generate_action_plan(self, findings: List[Any]) -> List[Dict[str, str]]:
        """Return prioritized actions based on CVSS and Severity, aggregated by issue type."""
        # Group by message/remediation to aggregate targets
        grouped = {}
        for f in findings:
            # Key: (Message, Remediation, Severity)
            key = (f.message, f.remediation, f.severity)
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(f.target)
            
        # Sort groups by Severity (Critical > High...)
        severity_map = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
        
        sorted_groups = sorted(
            grouped.items(),
            key=lambda x: severity_map.get(x[0][2], 0),
            reverse=True
        )
        
        top_actions = []
        for (msg, rem, sev), targets in sorted_groups:
            # Create a granular action item
            # If many targets, summarize. If few, list them.
            if len(targets) > 3:
                target_str = f"{len(targets)} assets (e.g., {', '.join(targets[:2])}...)"
            else:
                target_str = ", ".join(targets)

            action = {
                "priority": "Immediate" if sev in ['CRITICAL', 'HIGH'] else "Strategic",
                "finding": msg,
                "step": rem,
                "target": target_str,
                "count": len(targets),
                "severity": sev
            }
            top_actions.append(action)
            
            # Limit to top 10 for granularity (user requested "numero molto granulare")
            if len(top_actions) >= 10:
                break
                
        return top_actions

    def _build_html(self, report, risks: List[BusinessRisk], metrics: Dict[str, Any], action_plan: List[Dict[str, str]]) -> str:
        """Construct the final HTML string."""
        
        # 1. Headline
        html = f"""
        <div style="margin-bottom: 20px;">
            <p class="executive-text">
                <strong>Audit Status:</strong> <span style="color: {'#ef4444' if metrics['status'] == 'CRITICAL' else '#eab308' if metrics['status'] == 'IMPROVEMENT NEEDED' else '#10b981'}">{metrics['status']}</span> 
                (Score: {metrics['score']}/100)
            </p>
            <p class="executive-text">
                The comprehensive audit of <strong>{report.stats.get('analyzed_hosts', 0)} assets</strong> identified 
                <strong>{metrics['total_findings']} compliance gaps</strong>, including 
                <strong>{metrics['critical_count']} Critical</strong> and 
                <strong>{metrics['high_count']} High</strong> severity vulnerabilities.
            </p>
        </div>
        """

        # 2. Business Risks
        if risks:
            html += """<div style="margin-bottom: 20px;"><strong style="color: var(--primary);">Key Business Risks:</strong><ul style="margin-top: 10px;">"""
            for risk in risks:
                html += f"""
                <li style="margin-bottom: 8px;">
                    <strong>{risk.name}:</strong> {risk.impact}
                </li>
                """
            html += "</ul></div>"
        
        # 3. Strategic Action Plan
        if action_plan:
            html += """<div><strong style="color: var(--primary);">Strategic Priorities (Top 10):</strong><ol style="margin-top: 10px;">"""
            for action in action_plan:
                priority_color = "#ef4444" if action['priority'] == "Immediate" else "#3b82f6"
                html += f"""
                <li style="margin-bottom: 8px;">
                    <strong style="color: {priority_color};">{action['priority']}:</strong> {action['step']} 
                    <div style="font-size: 0.85em; color: var(--text-muted); margin-top: 2px;">
                        Issue: {action['finding']} | Affects: {action['target']}
                    </div>
                </li>
                """
            html += "</ol></div>"

        return html
