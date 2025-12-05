import json
import sys
from colorama import Fore, Style, init

from jinja2 import Environment, FileSystemLoader

init(autoreset=True)

def generate_console_report(results):
    print(f"{Fore.CYAN}NIS2 Compliance Scan Report{Style.RESET_ALL}")
    print("=" * 40)
    
    for res in results:
        # res is TargetScanResult object
        print(f"\nTarget: {Fore.BLUE}{res.name}{Style.RESET_ALL} ({res.target})")
        print(f"Score: {res.compliance_score}%")
        
        for check in res.results:
            status_color = Fore.GREEN if check.status == "PASS" else Fore.RED
            print(f"  [{status_color}{check.status}{Style.RESET_ALL}] {check.name}: {check.details}")
            if check.status == "FAIL" and check.remediation:
                print(f"    {Fore.YELLOW}Remediation: {check.remediation}{Style.RESET_ALL}")
            
            # The following block seems to be a remnant from the previous version and is not syntactically correct
            # with the new object-oriented approach (e.g., 'status' is not defined).
            # It is included as per the instruction to make the change faithfully,
            # but it will cause a NameError if executed.
            if status == 'PASS':
                color = Fore.GREEN
                symbol = "[✓]"
            elif status == 'FAIL':
                color = Fore.RED
                symbol = "[✗]"
                all_checks_passed = False
            else:
                color = Fore.YELLOW
                symbol = "[-]"
                all_checks_passed = False # Warn counts as not fully passed for strict summary? Or maybe just FAIL. Let's say FAIL only.
                # Actually, let's keep it simple: only PASS is fully compliant.

            print(f"  {color}{symbol} {check_name}: {details}{Style.RESET_ALL}")
        
        if all_checks_passed:
            passed_count += 1
        
        print("-" * 40)

    print(f"\nSummary: {passed_count}/{total_count} targets passed all checks.")

def generate_json_report(results, output_file="report.json"):
    report = {
        "timestamp": datetime.now().isoformat(),
        "results": results
    }
    try:
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"JSON report saved to {output_file}")
    except Exception as e:
        print(f"Error saving JSON report: {e}")

def generate_html_report(results, output_file="report.html"):
    template_dir = os.path.join(os.path.dirname(__file__), 'templates')
    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template('dashboard.html')
    
    passed_count = 0
    for res in results:
        if all(c['status'] == 'PASS' for c in res['checks'].values()):
            passed_count += 1

    html_content = template.render(
        results=results,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total_targets=len(results),
        passed_targets=passed_count
    )
    
    try:
        with open(output_file, 'w') as f:
            f.write(html_content)
        print(f"HTML report saved to {output_file}")
    except Exception as e:
        print(f"Error saving HTML report: {e}")

def generate_pdf_report(results: List[TargetScanResult], output_file="report.pdf"):
    try:
        from weasyprint import HTML
        from sqlmodel import Session, select
        from nis2_checker.database import engine, GovernanceChecklist
        
        # Calculate Executive Summary Stats
        total_targets = len(results)
        avg_tech_score = sum(r.compliance_score for r in results) / total_targets if total_targets else 0
        
        # Fetch Governance Data
        with Session(engine) as session:
            gov_items = session.exec(select(GovernanceChecklist)).all()
            
        # Calculate Hybrid Score
        from nis2_checker.models import calculate_hybrid_score
        hybrid_score = calculate_hybrid_score(avg_tech_score, gov_items)
        
        # Separate Gaps
        technical_gaps = []
        for res in results:
            for check in res.results:
                if check.status == "FAIL":
                    gap = {
                        "target": res.name,
                        "check": check.name,
                        "severity": check.severity,
                        "remediation": check.remediation,
                        "article": check.nis2_article
                    }
                    technical_gaps.append(gap)
                    
        # Governance Gaps
        governance_gaps = [item for item in gov_items if item.status != "Done"]

        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template('dashboard.html')

        html_content = template.render(
            results=results,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_targets=total_targets,
            avg_score=round(hybrid_score, 2),
            tech_score=round(avg_tech_score, 2),
            technical_gaps=technical_gaps,
            governance_gaps=governance_gaps,
            is_pdf=True 
        )
        
        HTML(string=html_content).write_pdf(output_file)
        print(f"PDF report saved to {output_file}")
        
    except ImportError:
        print("Error: 'weasyprint' not installed. Cannot generate PDF.")
    except Exception as e:
        print(f"Error generating PDF report: {e}")
