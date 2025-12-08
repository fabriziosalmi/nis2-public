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
        
        # Ransomware Risk (SMB/RDP)
        ransomware_findings = [f for f in findings if "SMB" in f.message or "RDP" in f.message]
        if ransomware_findings:
            risks.append(BusinessRisk(
                name="Ransomware & Lateral Movement",
                impact="Critical. Exposed administrative ports (SMB/RDP) allow attackers to deploy ransomware directly into the network.",
                probability="High",
                related_findings=ransomware_findings
            ))

        # Data Leakage (Zone Transfer, Databases)
        leak_findings = [f for f in findings if "Zone Transfer" in f.message or "Database" in f.message or "FTP" in f.message or "Telnet" in f.message]
        if leak_findings:
            risks.append(BusinessRisk(
                name="Data Leakage & Espionage",
                impact="High. Unprotected data stores or legacy protocols allow unauthorized access to sensitive intellectual property.",
                probability="Medium",
                related_findings=leak_findings
            ))

        # Supply Chain / Integrity (DNSSEC, SSL)
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
        """Return top 3 prioritized actions based on CVSS and Severity."""
        # Sort by Severity (Critical > High...) and CVSS desc
        severity_map = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
        
        sorted_findings = sorted(
            findings, 
            key=lambda f: (severity_map.get(f.severity, 0), getattr(f, 'cvss_base_score', 0)), 
            reverse=True
        )
        
        top_actions = []
        seen_messages = set()
        
        for f in sorted_findings:
            if f.message in seen_messages:
                continue
            seen_messages.add(f.message)
            
            action = {
                "priority": "Immediate" if f.severity in ['CRITICAL', 'HIGH'] else "Strategic",
                "finding": f.message,
                "step": f.remediation,
                "target": f.target
            }
            top_actions.append(action)
            if len(top_actions) >= 3:
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
            html += """<div><strong style="color: var(--primary);">Strategic Priorities (Top 3):</strong><ol style="margin-top: 10px;">"""
            for action in action_plan:
                html += f"""
                <li style="margin-bottom: 8px;">
                    <strong>{action['priority']}:</strong> {action['step']} 
                    <span style="font-size: 0.85em; color: var(--text-muted);">(Ref: {action['target']} - {action['finding']})</span>
                </li>
                """
            html += "</ol></div>"

        return html
