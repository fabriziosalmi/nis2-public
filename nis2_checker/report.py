import json
import sys
import os
import csv
from datetime import datetime
from typing import List
from xml.etree.ElementTree import Element, SubElement, tostring, ElementTree
from colorama import Fore, Style, init

from jinja2 import Environment, FileSystemLoader
from nis2_checker.models import TargetScanResult

init(autoreset=True)

def generate_console_report(results):
    print(f"{Fore.CYAN}NIS2 Compliance Scan Report{Style.RESET_ALL}")
    print("=" * 40)
    
    passed_count = 0
    total_count = len(results)

    for res in results:
        # res is TargetScanResult object
        print(f"\nTarget: {Fore.BLUE}{res.name}{Style.RESET_ALL} ({res.target})")
        print(f"Score: {res.compliance_score}%")
        
        all_checks_passed = True
        for check in res.results:
            status_color = Fore.GREEN if check.status == "PASS" else (Fore.RED if check.status == "FAIL" else Fore.YELLOW)
            print(f"  [{status_color}{check.status}{Style.RESET_ALL}] {check.name}: {check.details}")
            if check.status == "FAIL":
                all_checks_passed = False
                if check.remediation:
                    print(f"    {Fore.YELLOW}Remediation: {check.remediation}{Style.RESET_ALL}")
        
        if all_checks_passed:
            passed_count += 1
        
        print("-" * 40)

    print(f"\nSummary: {passed_count}/{total_count} targets passed all checks.")

def generate_json_report(results, output_file="report.json"):
    # Convert SQLModel objects to dicts
    results_dict = [res.model_dump() for res in results]
    
    report = {
        "timestamp": datetime.now().isoformat(),
        "results": results_dict
    }
    try:
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"JSON report saved to {output_file}")
    except Exception as e:
        print(f"Error saving JSON report: {e}")

def generate_html_report(results, output_file="report.html"):
    template_dir = os.path.join(os.path.dirname(__file__), 'templates')
    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template('dashboard.html')
    
    passed_count = 0
    for res in results:
        # Check if all checks passed
        all_passed = True
        for check in res.results:
            if check.status != 'PASS':
                all_passed = False
                break
        
        if all_passed:
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

def generate_markdown_report(results: List[TargetScanResult], output_file="report.md"):
    """Generates a GitHub-flavored Markdown report."""
    with open(output_file, 'w') as f:
        f.write("# NIS2 Compliance Scan Report\n\n")
        f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Total Targets:** {len(results)}\n\n")
        
        # Summary Table
        f.write("## Summary\n")
        f.write("| Target | Score | Status | Critical Issues |\n")
        f.write("|---|---|---|---|\n")
        for res in results:
            status = "✅ PASS" if res.compliance_score == 100 else ("⚠️ WARN" if res.compliance_score > 50 else "❌ FAIL")
            crit_count = sum(1 for c in res.results if c.severity == 'CRITICAL' and c.status == 'FAIL')
            f.write(f"| {res.name} | {res.compliance_score}% | {status} | {crit_count} |\n")
        
        f.write("\n## Detailed Results\n")
        for res in results:
            f.write(f"### {res.name} ({res.target})\n")
            f.write(f"**Compliance Score:** {res.compliance_score}%\n\n")
            
            # Failures first
            failures = [c for c in res.results if c.status == 'FAIL']
            if failures:
                f.write("#### ❌ Failures\n")
                for c in failures:
                    f.write(f"- **{c.name}** ({c.severity}): {c.details}\n")
                    if c.remediation:
                        f.write(f"  - *Remediation: {c.remediation}*\n")
            
            # Warnings
            warnings = [c for c in res.results if c.status not in ['PASS', 'FAIL']]
            if warnings:
                f.write("\n#### ⚠️ Warnings\n")
                for c in warnings:
                    f.write(f"- **{c.name}**: {c.details}\n")
            
            f.write("\n---\n")
            
    print(f"Markdown report saved to {output_file}")

def generate_csv_report(results: List[TargetScanResult], output_file="report.csv"):
    """Generates a CSV report with one row per check."""
    try:
        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = ['target_name', 'target_url', 'check_name', 'status', 'severity', 'details', 'remediation', 'nis2_article']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for res in results:
                for check in res.results:
                    writer.writerow({
                        'target_name': res.name,
                        'target_url': res.target,
                        'check_name': check.name,
                        'status': check.status,
                        'severity': check.severity,
                        'details': check.details,
                        'remediation': check.remediation or "",
                        'nis2_article': check.nis2_article or ""
                    })
        print(f"CSV report saved to {output_file}")
    except Exception as e:
        print(f"Error saving CSV report: {e}")

def generate_junit_report(results: List[TargetScanResult], output_file="junit_report.xml"):
    """Generates a JUnit XML report for CI integration."""
    testsuites = Element('testsuites')
    
    for res in results:
        testsuite = SubElement(testsuites, 'testsuite', name=res.name, tests=str(len(res.results)))
        
        for check in res.results:
            testcase = SubElement(testsuite, 'testcase', name=check.name, classname=res.name)
            
            if check.status == 'FAIL':
                failure = SubElement(testcase, 'failure', message=check.details, type=check.severity)
                failure.text = f"Remediation: {check.remediation}\nDetails: {check.details}"
            elif check.status == 'WARN':
                # JUnit doesn't strictly have 'warn', mostly skipped or passed with stdout
                # We'll treat as passed but add stdout? Or skipped? 
                # Let's add system-out
                system_out = SubElement(testcase, 'system-out')
                system_out.text = f"WARNING: {check.details}"
    
    tree = ElementTree(testsuites)
    try:
        tree.write(output_file, encoding='utf-8', xml_declaration=True)
        print(f"JUnit report saved to {output_file}")
    except Exception as e:
        print(f"Error saving JUnit report: {e}")
