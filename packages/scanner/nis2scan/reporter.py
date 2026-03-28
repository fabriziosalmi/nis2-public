import os
import json
import dataclasses
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from jinja2 import Environment, FileSystemLoader
from .compliance import ComplianceReport

class ParamEncoder(json.JSONEncoder):
    def default(self, obj):
        if dataclasses.is_dataclass(obj):
            return dataclasses.asdict(obj)
        return super().default(obj)

class Reporter:
    def __init__(self, output_dir="reports"):
        self.console = Console()
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        # Setup Jinja2
        template_dir = os.path.join(os.getcwd(), 'templates')
        # Fallback if specific path needed or embedded, but usually relative to pwd
        if not os.path.exists(template_dir):
             # Try to find it relative to package? For now assume pwd/templates 
             pass
        
        self.env = Environment(loader=FileSystemLoader(template_dir))

    def print_to_console(self, report: ComplianceReport):
        self.console.print("\n")
        
        score_color = "red"
        if report.total_score > 80: score_color = "green"
        elif report.total_score > 50: score_color = "yellow"
        
        self.console.print(Panel(f"[bold blue]NIS2 Compliance Report[/bold blue]\nScore: [bold {score_color}]{report.total_score}/100[/bold {score_color}]", expand=False))
        
        # Stats Table
        table = Table(title="Scan Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")
        for k, v in report.stats.items():
            table.add_row(k.replace('_', ' ').title(), str(v))
        self.console.print(table)
        
        # Checks performed
        self.console.print("\n[bold]Checks Performed:[/bold]")
        for c in report.checked_items:
             self.console.print(f"- {c}")

        self.console.print("\n[bold]Key Findings[/bold]")
        
        # Findings Table
        ftable = Table(show_header=True, header_style="bold white", width=160)
        ftable.add_column("Severity")
        ftable.add_column("CVSS") # Added
        ftable.add_column("Target")
        ftable.add_column("Issue")
        ftable.add_column("Remediation", style="green") # Added
        ftable.add_column("Reference")
        
        for f in report.findings:
            color = "white"
            if f.severity == "CRITICAL": color = "red bold blink"
            elif f.severity == "HIGH": color = "red"
            elif f.severity == "MEDIUM": color = "yellow"
            
            ftable.add_row(
                Text(f.severity, style=f"bold {color}"),
                str(f.cvss_base_score),
                f.target,
                f.message,
                f.remediation, # Added
                f.reference
            )
            
        self.console.print(ftable)
        self.console.print("\n")

    def save_json(self, report: ComplianceReport, filename="nis2_report.json"):
        import datetime
        
        # JSON Schema v2.0
        output_data = {
            "version": "2.0",
            "metadata": {
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "generator": "NIS2 Compliance Scanner",
            },
            "summary": {
                "total_score": report.total_score,
                "stats": report.stats,
                "checked_items": report.checked_items
            },
            "compliance_matrix": report.compliance_matrix,
            "assets": report.assets,
            "findings": [dataclasses.asdict(f) for f in report.findings]
        }
        
        path = os.path.join(self.output_dir, filename)
        with open(path, "w") as f:
            json.dump(output_data, f, indent=4)
        self.console.print(f"[green]JSON Report saved to {path}[/green]")

    def save_html(self, report: ComplianceReport, filename="nis2_report.html"):
        path = os.path.join(self.output_dir, filename)
        
        # Load CSS/JS
        try:
            with open(os.path.join(os.getcwd(), 'templates', 'report.css'), 'r') as f:
                css_content = f.read()
            with open(os.path.join(os.getcwd(), 'templates', 'report.js'), 'r') as f:
                js_content = f.read()
        except Exception as e:
            self.console.print(f"[yellow]Warning: Could not load template assets: {e}[/yellow]")
            css_content = ""
            js_content = ""

        try:
            template = self.env.get_template("report_template.html")
            html_out = template.render(
                report=report,
                css_content=css_content,
                js_content=js_content
            )
            with open(path, "w") as f:
                f.write(html_out)
            self.console.print(f"[green]HTML Report saved to {path}[/green]")
        except Exception as e:
             self.console.print(f"[red]Failed to generate HTML report: {e}[/red]")

    def save_markdown(self, report: ComplianceReport, filename="nis2_report.md"):
        path = os.path.join(self.output_dir, filename)
        with open(path, "w") as f:
            f.write(f"# NIS2 Compliance Report\n")
            f.write(f"**Compliance Score**: {report.total_score}/100\n\n")
            
            f.write("## Executive Summary\n")
            f.write(f"{report.executive_summary}\n\n")

            f.write("## Statistics\n")
            for k, v in report.stats.items():
                f.write(f"- **{k.replace('_', ' ').title()}**: {v}\n")
            
            f.write("\n## Checks Performed\n")
            for c in report.checked_items:
                f.write(f"- {c}\n")

            f.write("\n## Findings\n")
            f.write("| Severity | CVSS | Target | Issue | Technical Detail | Remediation | Reference |\n")
            f.write("|----------|------|--------|-------|------------------|-------------|-----------|\n")
            for fo in report.findings:
                f.write(f"| {fo.severity} | {fo.cvss_base_score} | {fo.target} | {fo.message} | {fo.technical_detail} | {fo.remediation} | {fo.reference} |\n")
        
        self.console.print(f"[green]Markdown Report saved to {path}[/green]")
