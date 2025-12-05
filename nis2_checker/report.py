import json
import sys
from colorama import Fore, Style, init

from jinja2 import Environment, FileSystemLoader

init(autoreset=True)

def generate_console_report(results):
    print("\n" + "="*60)
    print("NIS2 Compliance Check Report")
    print("="*60 + "\n")

    passed_count = 0
    total_count = len(results)

    for result in results:
        print(f"Target: {result['name']} ({result['target']})")
        
        all_checks_passed = True
        for check_name, check_data in result['checks'].items():
            status = check_data['status']
            details = check_data['details']
            
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

def generate_pdf_report(results, output_file="report.pdf"):
    try:
        from weasyprint import HTML
        
        # Generate HTML content first (reuse logic or call internal helper)
        # For simplicity, we'll regenerate the HTML string here using the same template
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
        
        HTML(string=html_content).write_pdf(output_file)
        print(f"PDF report saved to {output_file}")
        
    except ImportError:
        print("Error: 'weasyprint' not installed. Cannot generate PDF.")
    except Exception as e:
        print(f"Error generating PDF report: {e}")
