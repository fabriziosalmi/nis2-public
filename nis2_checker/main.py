import argparse
import sys
import asyncio
import json
import os
from nis2_checker.config import load_config, load_targets
from nis2_checker.report import generate_console_report, generate_json_report, generate_html_report, generate_pdf_report
from nis2_checker.database import create_db_and_tables, get_session, ScanResult
from nis2_checker.notifier import send_alert

async def scan_single_target(scanner, target):
    """Runs the async scanner for a target."""
    return await scanner.scan_target(target)

async def main_async():
    parser = argparse.ArgumentParser(description="NIS2 Compliance Checker")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command: scan (default)
    scan_parser = subparsers.add_parser("scan", help="Run compliance scan")
    scan_parser.add_argument("--config", default="config.yaml", help="Path to configuration file")
    scan_parser.add_argument("--targets", default="targets.yaml", help="Path to targets file")
    scan_parser.add_argument("--output", help="Output file for JSON report (overrides config)")

    # Command: report-incident
    report_parser = subparsers.add_parser("report-incident", help="Interactive Incident Reporting Helper (Art. 23)")

    # Workaround for default behavior (if no command, assume 'scan')
    if len(sys.argv) == 1:
        args = parser.parse_args(['scan'])
    else:
        # If user passed arguments but no command (e.g. --config), assume scan
        # This is tricky with argparse, so we'll just check if the first arg is a known command
        if sys.argv[1] not in ['scan', 'report-incident', '-h', '--help']:
             # Insert 'scan' at index 1
             sys.argv.insert(1, 'scan')
        args = parser.parse_args()

    # --- HANDLE INCIDENT REPORTING ---
    if args.command == "report-incident":
        from nis2_checker.incident_reporter import IncidentReporter
        reporter = IncidentReporter()
        reporter.run_interactive()
        return

    # --- HANDLE SCAN ---
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
    # Determine formats from config or CLI override (if we wanted to add --format flag, but user asked for --output logic improvement)
    # The current CLI has --output which overrides the FILE path, but not the format.
    # Config has 'format': 'console' or 'json' etc.
    
    # Let's separate format and output file logic.
    # If user wants multiple formats, they might expect multiple files.
    # We will assume config['report']['formats'] is a list or comma-string.
    
    config_formats = config.get('report', {}).get('formats', ['console'])
    if isinstance(config_formats, str):
        config_formats = config_formats.split(',')
        
    # Backward compatibility for 'format' key
    if 'format' in config.get('report', {}):
        legacy_fmt = config['report']['format']
        if legacy_fmt and legacy_fmt not in config_formats:
            config_formats.append(legacy_fmt)

    # CLI Output override: if --output is provided, we try to guess format from extension
    # OR we just generate that specific file.
    if args.output:
        ext = os.path.splitext(args.output)[1].lower().strip('.')
        if ext == 'json':
            generate_json_report(results, args.output)
        elif ext == 'pdf':
            generate_pdf_report(results, args.output)
        elif ext == 'html':
            generate_html_report(results, args.output)
        elif ext == 'md':
            from nis2_checker.report import generate_markdown_report
            generate_markdown_report(results, args.output)
        elif ext == 'csv':
             from nis2_checker.report import generate_csv_report
             generate_csv_report(results, args.output)
        elif ext == 'xml':
             from nis2_checker.report import generate_junit_report
             generate_junit_report(results, args.output)
        else:
             print(f"Unknown output extension '{ext}', defaulting to JSON.")
             generate_json_report(results, args.output)
             
    # Generate configured formats (default behavior)
    if 'console' in config_formats or 'both' in config_formats:
        generate_console_report(results)
        
    base_filename = config.get('report', {}).get('output_file', 'report')
    base_name, _ = os.path.splitext(base_filename)
    
    if 'json' in config_formats or 'both' in config_formats:
        generate_json_report(results, base_name + '.json')
        
    if 'html' in config_formats:
        generate_html_report(results, base_name + '.html')

    if 'pdf' in config_formats:
        generate_pdf_report(results, base_name + '.pdf')
        
    if 'md' in config_formats or 'markdown' in config_formats:
        from nis2_checker.report import generate_markdown_report
        generate_markdown_report(results, base_name + '.md')

    if 'csv' in config_formats:
        from nis2_checker.report import generate_csv_report
        generate_csv_report(results, base_name + '.csv')

    if 'junit' in config_formats or 'xml' in config_formats:
        from nis2_checker.report import generate_junit_report
        generate_junit_report(results, base_name + '.xml')

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
