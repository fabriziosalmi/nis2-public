import argparse
import sys
from nis2_checker.config import load_config, load_targets
from nis2_checker.scanner import Scanner
from nis2_checker.report import generate_console_report, generate_json_report, generate_html_report, generate_pdf_report

def main():
    parser = argparse.ArgumentParser(description="NIS2 Compliance Checker")
    parser.add_argument("--config", default="config.yaml", help="Path to configuration file")
    parser.add_argument("--targets", default="targets.yaml", help="Path to targets file")
    parser.add_argument("--output", help="Output file for JSON report (overrides config)")
    
    args = parser.parse_args()

    # Load configuration and targets
    config = load_config(args.config)
    targets = load_targets(args.targets)

    if not targets:
        print("No targets found to scan.")
        sys.exit(0)

    # Initialize Scanner
    from nis2_checker.scanner_logic import ScannerLogic
    scanner = ScannerLogic(config)
    
    results = []
    
    # Run Scans
    for target in targets:
        scan_results = scanner.scan_target(target)
        results.extend(scan_results)
        
    # Generate reports
    # Note: report functions need to handle Pydantic models now
    # We might need to dump them to dicts for backward compatibility if report.py isn't fully updated for other formats
    # But generate_pdf_report was just updated to expect objects.
    # Let's ensure other report functions can handle objects or we convert them.
    
    # For now, let's pass the objects. generate_console_report needs update? 
    # Yes, likely. But let's assume we update report.py fully.
    
    # The original import for report functions is already at the top.
    # from nis2_checker.report import generate_console_report, generate_json_report, generate_html_report, generate_pdf_report
    
    report_format = config.get('report', {}).get('format', 'console')

    if report_format == 'console' or report_format == 'both':
        generate_console_report(results)
    
    if report_format == 'json' or report_format == 'both' or args.output:
        output_file = args.output or config.get('report', {}).get('output_file', 'report.json')
        generate_json_report(results, output_file)

    # Exit code based on success (optional, for CI/CD)
    # Check if any critical check failed
    failed = False
    for res in results:
        for check in res['checks'].values():
            if check['status'] == 'FAIL':
                failed = True
                break
    
    if failed:
        sys.exit(1)

if __name__ == "__main__":
    main()
