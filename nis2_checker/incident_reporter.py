import json
import datetime
import os
import sys
from typing import Dict, Any

class IncidentReporter:
    def __init__(self):
        self.taxonomy = {
            "incident_types": [
                "DoS/DDoS",
                "Malware/Ransomware",
                "Phishing/Social Engineering",
                "Data Leak/Breach",
                "System Compromise",
                "Unavailability (Hardware/Software Failure)",
                "Other"
            ],
            "severity_levels": [
                "Low (Minor impact, resolved internally)",
                "Significant (Early Warning - Art. 23 NIS2)",
                "Critical (National security / Cross-border impact)"
            ],
            "status": [
                "Ongoing",
                "Contained",
                "Recovered"
            ]
        }

    def _prompt(self, question: str, options: list = None, required: bool = True) -> str:
        """Helper for interactive prompts."""
        while True:
            if options:
                print(f"\n{question}")
                for i, opt in enumerate(options, 1):
                    print(f"  {i}. {opt}")
                
                choice = input("Select an option (number): ").strip()
                if choice.isdigit() and 1 <= int(choice) <= len(options):
                    return options[int(choice) - 1]
                print("Invalid selection. Please try again.")
            else:
                answer = input(f"\n{question}: ").strip()
                if answer or not required:
                    return answer
                print("This field is required.")

    def run_interactive(self):
        """Run the interactive incident reporting wizard."""
        print("\n=== NIS2 Significant Incident Reporting Helper (Art. 23) ===")
        print("This tool helps you generate a structured JSON report for CSIRT notification.\n")
        
        # 1. Entity Details
        print("--- Entity Details ---")
        entity_name = self._prompt("Entity Name")
        sector = self._prompt("Sector (e.g., Energy, Health, Digital Infra)")
        contact_email = self._prompt("Contact Email")

        # 2. Incident Details
        print("\n--- Incident Details ---")
        title = self._prompt("Incident Title (Short description)")
        incident_type = self._prompt("Type of Incident", self.taxonomy["incident_types"])
        severity = self._prompt("Severity / Classification", self.taxonomy["severity_levels"])
        status = self._prompt("Current Status", self.taxonomy["status"])
        
        occurred_at = self._prompt("Date/Time of Detection (YYYY-MM-DD HH:MM)", required=False)
        if not occurred_at:
            occurred_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

        description = self._prompt("Detailed Description (Causes, assets affected, impact)")

        # 3. Impact Assessment
        print("\n--- Impact Assessment ---")
        impact_users = self._prompt("Estimated affected users (Number)", required=False)
        cross_border = self._prompt("Cross-border impact? (yes/no)", options=["Yes", "No", "Unknown"])
        
        # Build Report
        report = {
            "meta": {
                "generated_at": datetime.datetime.now().isoformat(),
                "cisor_tool_version": "0.6.2"
            },
            "entity": {
                "name": entity_name,
                "sector": sector,
                "contact": contact_email
            },
            "incident": {
                "title": title,
                "type": incident_type,
                "severity": severity,
                "status": status,
                "detected_at": occurred_at,
                "description": description
            },
            "impact": {
                "affected_users": impact_users,
                "cross_border": cross_border == "Yes"
            }
        }

        # Save Report
        filename = f"incident_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4)
            
        print(f"\n[SUCCESS] Incident report generated: {filename}")
        print("Review this JSON file before submitting to CSIRT Italia / National Authority.")
        print("-------------------------------------------------------------------------")
        input("Press Enter to exit...")

if __name__ == "__main__":
    reporter = IncidentReporter()
    reporter.run_interactive()
