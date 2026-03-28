import json
import os
from datetime import datetime
from rich.prompt import Prompt, Confirm
from rich.console import Console

console = Console()

class IncidentReporter:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def interactive_questions(self):
        console.print("[bold red]NIS2 Article 23 - Early Warning Report Generator[/bold red]")
        console.print("This tool helps you generate a standardized incident report for your CSIRT.\n")

        data = {}
        
        # 1. Organization Details
        console.print("[bold]1. Organization Details[/bold]")
        data["organization_name"] = Prompt.ask("Organization Name")
        data["contact_email"] = Prompt.ask("Contact Email")
        
        # 2. Incident Timeline
        console.print("\n[bold]2. Incident Timeline[/bold]")
        data["detection_time"] = Prompt.ask("Detection Time (YYYY-MM-DD HH:MM)", default=datetime.now().strftime("%Y-%m-%d %H:%M"))
        data["is_ongoing"] = Confirm.ask("Is the incident currently ongoing?", default=True)
        
        # 3. Impact Assessment
        console.print("\n[bold]3. Impact Assessment[/bold]")
        data["impact_category"] = Prompt.ask(
            "Impact Category", 
            choices=["Service Unavailable", "Data Leak", "Malware/Ransomware", "Social Engineering", "Other"], 
            default="Service Unavailable"
        )
        data["affected_systems"] = Prompt.ask("Number of affected systems/users").strip()
        data["severity"] = Prompt.ask("Severity Level", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default="HIGH")
        
        # 4. Cross-border & Supply Chain
        console.print("\n[bold]4. Context[/bold]")
        data["cross_border"] = Confirm.ask("Does this incident affect other EU member states?", default=False)
        data["supply_chain"] = Confirm.ask("Does this incident impact your supply chain or customers?", default=False)
        
        # 5. Technical Details
        console.print("\n[bold]5. Technical Indicators[/bold]")
        data["indicators"] = Prompt.ask("IOCs (IPs, Hashes, URLs) - optional", default="").strip()
        data["description"] = Prompt.ask("Brief Description of the Incident")

        return data

    def generate_report(self, data):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename_json = f"incident_report_{timestamp}.json"
        filepath_json = os.path.join(self.output_dir, filename_json)

        # JSON Export
        with open(filepath_json, "w") as f:
            json.dump(data, f, indent=4)

        console.print(f"\n[bold green]Report Generated Successfully![/bold green]")
        console.print(f"JSON Report: [link=file://{os.path.abspath(filepath_json)}]{filepath_json}[/link]")
        
        # Simple Text Summary for PDF-like view in console (or could generate actual PDF later)
        summary = f"""
        NIS2 EARLY WARNING REPORT (Art. 23)
        -----------------------------------
        Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        Organization: {data['organization_name']}
        
        [INCIDENT DETAILS]
        Category: {data['impact_category']}
        Severity: {data['severity']}
        Detected: {data['detection_time']}
        Ongoing: {data['is_ongoing']}
        
        [IMPACT]
        Systems Affected: {data['affected_systems']}
        Cross-Border Impact: {data['cross_border']}
        Supply Chain Impact: {data['supply_chain']}
        
        [DESCRIPTION]
        {data['description']}
        
        [IOCs]
        {data['indicators']}
        """
        
        filename_txt = f"incident_report_{timestamp}.txt"
        filepath_txt = os.path.join(self.output_dir, filename_txt)
        with open(filepath_txt, "w") as f:
            f.write(summary)
            
        console.print(f"Text Summary: [link=file://{os.path.abspath(filepath_txt)}]{filepath_txt}[/link]")
        console.print("\n[bold yellow]NEXT STEPS:[/bold yellow] Submit this report to your national CSIRT within 24 hours of detection.")

    def run(self):
        try:
            data = self.interactive_questions()
            self.generate_report(data)
        except KeyboardInterrupt:
            console.print("\n[bold red]Report generation cancelled.[/bold red]")
