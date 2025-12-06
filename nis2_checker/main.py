import argparse
import sys
import asyncio
import json
from nis2_checker.config import load_config, load_targets
from nis2_checker.report import generate_console_report, generate_json_report, generate_html_report, generate_pdf_report
from nis2_checker.database import create_db_and_tables, get_session, ScanResult
from nis2_checker.notifier import send_alert

async def scan_single_target(scanner, target):
    """Async wrapper for the synchronous scanner."""
    return await asyncio.to_thread(scanner.scan_target, target)

async def main_async():
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

    # Initialize Database
    create_db_and_tables()

    # Initialize Scanner
    from nis2_checker.scanner_logic import ScannerLogic
    scanner = ScannerLogic(config)
    
    print(f"Starting scan for {len(targets)} targets (Async Mode)...")
    
    # Run Scans in Parallel
    tasks = [scan_single_target(scanner, target) for target in targets]
    nested_results = await asyncio.gather(*tasks)
    
    # Flatten results (scan_target returns a list of TargetScanResult)
    results = [item for sublist in nested_results for item in sublist]
        
    # Process results: Save to DB & Alert
    session_gen = get_session()
    session = next(session_gen)
    
    try:
        for res in results:
            # DB Save
            critical_count = sum(1 for c in res.results if c.severity == 'CRITICAL' and c.status == 'FAIL')
            
            # Find SSL Status
            ssl_status = "N/A"
            for check in res.results:
                if check.check_id == 'ssl_tls':
                    ssl_status = check.status
                    break
                    
            db_entry = ScanResult(
                target_name=res.name,
                target_url=res.target or "N/A",
                compliance_score=res.compliance_score,
                ssl_status=ssl_status,
                critical_issues_count=critical_count,
                details=json.dumps([c.model_dump() for c in res.results], default=str)
            )
            session.add(db_entry)
            
            # Alerting
            if critical_count > 0:
                 critical_details = [f"{c.name}: {c.details}" for c in res.results if c.severity == 'CRITICAL' and c.status == 'FAIL']
                 webhook = config.get('notifications', {}).get('slack_webhook')
                 alert_on_fail = config.get('notifications', {}).get('alert_on', ['FAIL'])
                 
                 # Only alert if 'FAIL' is in alert_on config (rudimentary check, assuming user wants alerts on critical fails)
                 if webhook and "FAIL" in alert_on_fail:
                     send_alert(webhook, res.name, critical_details)

        session.commit()
    finally:
        session.close()

    # Generate reports
    report_format = config.get('report', {}).get('format', 'console')

    if report_format == 'console' or report_format == 'both':
        generate_console_report(results)
    
    if report_format == 'json' or report_format == 'both' or args.output:
        output_file = args.output or config.get('report', {}).get('output_file', 'report.json')
        generate_json_report(results, output_file)

    # PDF Report (Optional)
    if report_format == 'pdf':
         output_file = config.get('report', {}).get('output_file', 'report.pdf')
         generate_pdf_report(results, output_file)

    # Exit code based on success
    failed = False
    for res in results:
        for check in res.results:
            if check.status == 'FAIL':
                failed = True
                break
    
    if failed:
        sys.exit(1)

def main():
    asyncio.run(main_async())

if __name__ == "__main__":
    main()
