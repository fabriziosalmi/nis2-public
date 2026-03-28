import asyncio
import click
import logging
import os
import shutil
import yaml
from rich.logging import RichHandler
from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from .config import Config
from .scanner import Scanner
from .compliance import ComplianceEngine
from .reporter import Reporter
from .evidence import EvidenceCollector
from .exporter import PrometheusExporter
import dataclasses

# Setup logging
logging.basicConfig(
    level="INFO",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)

logger = logging.getLogger("nis2scan")

@click.group()
def cli():
    """NIS2 Compliance Scanner Tool."""
    pass

@cli.command()
@click.option('--output', '-o', default='config.yaml', help='Output configuration file path.')
def init(output):
    """Interactively generate a configuration file."""
    console = Console()
    console.print("[bold blue]NIS2 Configuration Generator[/bold blue]")
    console.print("This wizard will help you create a configuration file for the scanner.\n")

    config = {
        'project_name': Prompt.ask("Project Name", default="NIS2 Compliance Audit"),
        'scan_timeout': IntPrompt.ask("Scan Timeout (seconds)", default=10),
        'concurrency': IntPrompt.ask("Concurrency (threads)", default=50),
        'max_hosts': IntPrompt.ask("Max Hosts (0 for unlimited)", default=100),
        'targets': {
            'ip_ranges': [],
            'domains': [],
            'asns': []
        },
        'features': {
            'dns_checks': True,
            'web_checks': True,
            'port_scan': True,
            'whois_checks': True
        },
        'compliance_profile': "standard_nis2"
    }

    # Targets
    console.print("\n[bold]Targets[/bold]")
    console.print("[dim]Enter IP ranges (e.g. 192.168.1.0/24) or Domains one by one.[/dim]")
    
    while True:
        ip = Prompt.ask("Add IP Range (CIDR) [leave empty to skip/finish]", default="")
        if not ip:
            break
        config['targets']['ip_ranges'].append(ip)

    while True:
        domain = Prompt.ask("Add Domain [leave empty to skip/finish]", default="")
        if not domain:
            break
        config['targets']['domains'].append(domain)

    # Features
    console.print("\n[bold]Features[/bold]")
    config['features']['dns_checks'] = Confirm.ask("Enable DNS Security Checks?", default=True)
    config['features']['web_checks'] = Confirm.ask("Enable Web/HTTP Checks?", default=True)
    config['features']['port_scan'] = Confirm.ask("Enable Port Scanning?", default=True)
    config['features']['whois_checks'] = Confirm.ask("Enable WHOIS/Expiry Checks?", default=True)

    # Save
    try:
        with open(output, 'w') as f:
            yaml.dump(config, f, sort_keys=False, default_flow_style=False)
        console.print(f"\n[green]Configuration saved to {output}[/green]")
        console.print(f"[dim]You can now run the scan with: python -m nis2scan.cli scan -c {output}[/dim]")
    except Exception as e:
        console.print(f"\n[red]Error saving configuration: {e}[/red]")


@cli.command()
@click.option('--force', '-f', is_flag=True, help='Force deletion without confirmation.')
def clean(force):
    """Remove all generated reports and evidence."""
    console = Console()
    reports_dir = "reports"
    
    if not os.path.exists(reports_dir):
        console.print(f"[yellow]Directory '{reports_dir}' does not exist. Nothing to clean.[/yellow]")
        return

    if not force:
        if not Confirm.ask(f"Are you sure you want to delete all files in '{reports_dir}'?"):
            console.print("[yellow]Operation cancelled.[/yellow]")
            return

    deleted_count = 0
    try:
        for item in os.listdir(reports_dir):
            item_path = os.path.join(reports_dir, item)
            try:
                if os.path.isfile(item_path):
                    os.unlink(item_path)
                    deleted_count += 1
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
                    deleted_count += 1
            except Exception as e:
                console.print(f"[red]Failed to delete {item_path}: {e}[/red]")
        
        console.print(f"[green]Successfully cleaned up {deleted_count} items from '{reports_dir}'.[/green]")
    except Exception as e:
        console.print(f"[red]Error during cleanup: {e}[/red]")


@cli.command()
@click.option('--config', '-c', default='config.yaml', help='Path to configuration file.')
@click.option('--output', '-o', default='nis2_report.md', help='Output report file.')
@click.option('--limit', default=0, help='Max hosts to scan (0=unlimited).')
@click.option('--dry-run', is_flag=True, help='List targets without scanning.')
@click.option('--profile', default='default', help='Profile name for metrics (e.g. prod, dev).')
def scan(config, output, limit, dry_run, profile):
    """Run the compliance scan."""
    try:
        cfg = Config.load(config, max_hosts=limit, dry_run=dry_run)
        logger.info(f"Loaded configuration: {cfg.project_name}")
        logger.info(f"Targets: {len(cfg.targets.ip_ranges)} ranges, {len(cfg.targets.domains)} domains")
        if limit > 0: logger.info(f"Limit set to: {limit} hosts")
        if dry_run: logger.info("DRY RUN MODE ENABLED")
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        return

    # Initialize Evidence Collector (P0 Reproducibility)
    collector = EvidenceCollector()
    logger.info(f"Evidence Collection Initialized. Scan ID: {collector.scan_id}")
    
    # Freeze configuration
    # Note: Config object is nested, asdict handles it recursively? Yes.
    # But Config might have unserializable stuff? Mostly strings/lists.
    try:
        collector.freeze_config(dataclasses.asdict(cfg))
    except Exception as e:
        logger.warning(f"Could not freeze config: {e}")

    # Attach to config for Scanner to use
    cfg.evidence_collector = collector

    scanner = Scanner(cfg)
    logger.info("Starting scan... (this may take a while)")
    
    results = []
    try:
        # Phase 1: Target Resolution
        with click.progressbar(length=1, label='Resolving targets') as bar:
            # Note: We can't easily progress bar this part without knowing count ahead, 
            # but we can wrap the async call.
            # Let's just use status spinner from rich if we had it exposed, but we keep it simple.
            targets = asyncio.run(scanner.get_targets())
            bar.update(1)
        
        logger.info(f"Identified {len(targets)} targets to scan.")

        # Phase 2: Scanning
        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
        
        async def run_with_progress():
            scan_results = []
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeRemainingColumn(),
            ) as progress:
                task_id = progress.add_task("[cyan]Scanning...", total=len(targets))
                
                async for res in scanner.scan_targets(targets):
                    scan_results.append(res)
                    progress.update(task_id, advance=1)
            return scan_results

        results = asyncio.run(run_with_progress())
        logger.info(f"Scan complete. Analyzed {len(results)} hosts.")
    except Exception as e:
        logger.critical(f"Scan failed: {e}")
        return

    # Compliance Analysis
    logger.info("Analyzing compliance...")
    engine = ComplianceEngine(cfg)
    report = engine.evaluate(results, scan_id=collector.scan_id)
    
    # Reporting
    logger.info("Generating reports...")
    
    # Use timestamped name if default, or append if user specified
    # If user passed "nis2_report.md" (default), we change it to "nis2_report_<timestamp>"
    base_name = output.rsplit('.', 1)[0]
    if output == "nis2_report.md":
        base_name = f"nis2_report_{collector.scan_id}"
    elif output == "nis2_report.html":
        # Handle case if user specified html extension in default (though click default is .md)
        base_name = f"nis2_report_{collector.scan_id}"
    
    # Or generically, if the user didn't explicitly override with a custom path that shouldn't change...
    # Actually, user wants unique reports. Let's force unique name if it matches default pattern?
    # Simpler: If output was default, utilize scan_id.
    
    logger.info(f"Saving reports with base name: {base_name}")
    
    reporter = Reporter(output_dir="reports")
    reporter.print_to_console(report)
    
    # Save all formats
    reporter.save_markdown(report, f"{base_name}.md")
    reporter.save_json(report, f"{base_name}.json")
    reporter.save_html(report, f"{base_name}.html")

    # Finalize Evidence Bundle
    bundle_path = collector.finalize()
    logger.info(f"Verification Bundle created: {bundle_path}")

    # P1: Prometheus Metrics Export
    # We use the scan ID directory to store the metrics file as well, or a dedicated metrics dir?
    # User requested Node Exporter compatibility (textfile collector path).
    # Since we don't have a configured node_exporter path, we'll save it in the report dir
    # and print the path so user can symlink it.
    
    prom_path = os.path.join("reports", "nis2_metrics.prom")
    exporter = PrometheusExporter(profile_name=profile)
    exporter.update_metrics(report)
    exporter.export_to_file(prom_path)
    logger.info(f"Prometheus metrics saved to {prom_path} (Profile: {profile})")

@cli.command()
@click.option('--port', '-p', default=8000, help='Port to bind to.')
def serve(port):
    """Serve the reports directory via HTTP with enhanced index page."""
    directory = "reports"
    if not os.path.exists(directory):
        os.makedirs(directory)
        logger.info(f"Created {directory} directory.")
    
    # Generate custom index.html
    generate_index_page(directory)
    
    # Start file watcher for auto-updating homepage
    from .watcher import start_watcher
    observer = start_watcher(directory, generate_index_page)
    
    import http.server
    import socketserver
    
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=directory, **kwargs)
            
    with socketserver.TCPServer(("", port), Handler) as httpd:
        logger.info(f"Serving reports at http://0.0.0.0:{port}")
        logger.info("Press Ctrl+C to stop.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            logger.info("Stopping server and file watcher...")
            observer.stop()
            observer.join()
            logger.info("Server stopped.")


def generate_index_page(directory):
    """Generate an enhanced index.html with report cards."""
    import json
    import glob
    from datetime import datetime
    
    # Find all JSON reports
    json_files = sorted(glob.glob(os.path.join(directory, "nis2_report_*.json")), reverse=True)
    
    reports = []
    for json_file in json_files:
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
                # Extract key info
                basename = os.path.basename(json_file).replace('.json', '')
                html_file = basename + '.html'
                
                # Extract scan_id from filename (format: nis2_report_YYYYMMDD_HHMMSS.json)
                # basename is like "nis2_report_20251208_113914"
                parts = basename.split('_')
                if len(parts) >= 4:
                    scan_id = f"{parts[2]}_{parts[3]}"  # "20251208_113914"
                else:
                    scan_id = 'Unknown'
                
                # Parse timestamp from scan_id (format: YYYYMMDD_HHMMSS)
                try:
                    dt = datetime.strptime(scan_id, '%Y%m%d_%H%M%S')
                    formatted_date = dt.strftime('%d %b %Y, %H:%M')
                except:
                    formatted_date = 'Unknown date'
                
                # Count findings by severity
                findings = data.get('findings', [])
                severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
                for finding in findings:
                    sev = finding.get('severity', 'LOW')
                    if sev in severity_count:
                        severity_count[sev] += 1
                
                # Get stats from summary.stats path
                summary = data.get('summary', {})
                stats = summary.get('stats', {})
                
                reports.append({
                    'scan_id': scan_id,
                    'project_name': data.get('project_name', 'Network Audit'),
                    'score': summary.get('total_score', 0),
                    'findings_count': len(findings),
                    'analyzed_hosts': stats.get('analyzed_hosts', 0),
                    'html_file': html_file,
                    'formatted_date': formatted_date,
                    'severity': severity_count
                })
        except Exception as e:
            logger.warning(f"Could not parse {json_file}: {e}")
            continue
    
    # Generate HTML with professional styling matching report.css
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NIS2 Compliance Reports</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {{
            --primary: #0f172a;
            --secondary: #334155;
            --bg-body: #f8fafc;
            --bg-card: #ffffff;
            --text-main: #1e293b;
            --text-muted: #64748b;
            --border: #e2e8f0;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            background-color: var(--bg-body);
            color: var(--text-main);
            line-height: 1.5;
            min-height: 100vh;
            padding: 24px 16px;
            -webkit-font-smoothing: antialiased;
            font-size: 14px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        header {{
            margin-bottom: 24px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 16px;
        }}
        
        h1 {{
            font-size: 1.75rem;
            font-weight: 800;
            color: var(--primary);
            margin-bottom: 4px;
            letter-spacing: -0.025em;
        }}
        
        .subtitle {{
            font-size: 0.875rem;
            color: var(--text-muted);
        }}
        
        .stats-bar {{
            background: var(--bg-card);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 24px;
            display: flex;
            justify-content: center;
            gap: 32px;
            flex-wrap: wrap;
            border: 1px solid var(--border);
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }}
        
        .stat {{
            text-align: center;
        }}
        
        .stat-value {{
            font-size: 1.75rem;
            font-weight: 800;
            color: var(--primary);
            margin-bottom: 2px;
        }}
        
        .stat-label {{
            font-size: 0.7rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-weight: 600;
        }}
        
        .reports-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
            gap: 16px;
        }}
        
        .report-card {{
            background: var(--bg-card);
            border-radius: 8px;
            padding: 16px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            border: 1px solid var(--border);
            transition: transform 0.2s, box-shadow 0.2s;
            cursor: pointer;
            text-decoration: none;
            color: inherit;
            display: block;
        }}
        
        .report-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        }}
        
        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 8px;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--border);
            gap: 8px;
        }}
        
        .project-name {{
            font-size: 0.95rem;
            font-weight: 700;
            color: var(--primary);
            line-height: 1.3;
            flex: 1;
        }}
        
        .score-badge {{
            background: var(--primary);
            color: white;
            padding: 4px 10px;
            border-radius: 4px;
            font-weight: 700;
            font-size: 0.85rem;
            white-space: nowrap;
            flex-shrink: 0;
        }}
        
        .score-badge.good {{ background: #10b981; }}
        .score-badge.warning {{ background: #f59e0b; }}
        .score-badge.critical {{ background: #ef4444; }}
        
        .scan-date {{
            font-size: 0.75rem;
            color: var(--text-muted);
            margin-bottom: 6px;
        }}
        
        .scan-id {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.65rem;
            color: var(--text-muted);
            background: #f8fafc;
            padding: 4px 8px;
            border-radius: 4px;
            margin-bottom: 10px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}
        
        .severity-badges {{
            display: flex;
            gap: 4px;
            margin-bottom: 10px;
            flex-wrap: wrap;
        }}
        
        .severity-badge {{
            font-size: 0.625rem;
            padding: 2px 6px;
            border-radius: 3px;
            font-weight: 600;
            text-transform: uppercase;
            white-space: nowrap;
        }}
        
        .severity-badge.critical {{ background: #fee2e2; color: #dc2626; }}
        .severity-badge.high {{ background: #ffedd5; color: #ea580c; }}
        .severity-badge.medium {{ background: #fef9c3; color: #ca8a04; }}
        .severity-badge.low {{ background: #dbeafe; color: #2563eb; }}
        
        .card-stats {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 8px;
        }}
        
        .card-stat {{
            text-align: center;
            padding: 8px;
            background: #f8fafc;
            border-radius: 6px;
        }}
        
        .card-stat-value {{
            font-size: 1.25rem;
            font-weight: 700;
            color: var(--primary);
        }}
        
        .card-stat-label {{
            font-size: 0.625rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-weight: 600;
            margin-top: 2px;
        }}
        
        .empty-state {{
            text-align: center;
            padding: 60px 20px;
            background: var(--bg-card);
            border-radius: 12px;
            border: 1px dashed var(--border);
        }}
        
        .empty-state h2 {{
            font-size: 1.25rem;
            color: var(--primary);
            margin-bottom: 8px;
        }}
        
        .empty-state p {{
            color: var(--text-muted);
            font-size: 0.875rem;
        }}
        
        @media (max-width: 768px) {{
            body {{ padding: 16px 12px; }}
            h1 {{ font-size: 1.5rem; }}
            .subtitle {{ font-size: 0.8rem; }}
            .stats-bar {{ gap: 20px; padding: 12px; }}
            .stat-value {{ font-size: 1.5rem; }}
            .stat-label {{ font-size: 0.65rem; }}
            .reports-grid {{ grid-template-columns: 1fr; gap: 12px; }}
            .card-header {{ flex-direction: column; align-items: start; }}
            .score-badge {{ align-self: flex-start; }}
        }}
        
        @media (min-width: 1400px) {{
            .reports-grid {{ grid-template-columns: repeat(auto-fill, minmax(360px, 1fr)); }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>NIS2 Compliance Reports</h1>
            <p class="subtitle">Security & Compliance Intelligence Dashboard</p>
        </header>
        
        <div class="stats-bar">
            <div class="stat">
                <div class="stat-value">{len(reports)}</div>
                <div class="stat-label">Total Scans</div>
            </div>
            <div class="stat">
                <div class="stat-value">{sum(r['analyzed_hosts'] for r in reports)}</div>
                <div class="stat-label">Hosts Analyzed</div>
            </div>
            <div class="stat">
                <div class="stat-value">{sum(r['findings_count'] for r in reports)}</div>
                <div class="stat-label">Total Findings</div>
            </div>
        </div>
        
        {'<div class="reports-grid">' if reports else '<div class="empty-state"><h2>No Reports Yet</h2><p>Run a scan to generate your first compliance report</p></div>'}
"""
    
    for report in reports:
        score_class = 'good' if report['score'] >= 80 else 'warning' if report['score'] >= 50 else 'critical'
        
        # Build severity badges
        severity_html = ''
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = report['severity'][sev]
            if count > 0:
                severity_html += f'<span class="severity-badge {sev.lower()}">{count} {sev}</span>'
        
        html_content += f"""
            <a href="{report['html_file']}" class="report-card">
                <div class="card-header">
                    <div class="project-name">{report['project_name']}</div>
                    <div class="score-badge {score_class}">{report['score']}/100</div>
                </div>
                <div class="scan-date">📅 {report['formatted_date']}</div>
                <div class="scan-id">ID: {report['scan_id']}</div>
                <div class="severity-badges">{severity_html if severity_html else '<span class="severity-badge low">0 ISSUES</span>'}</div>
                <div class="card-stats">
                    <div class="card-stat">
                        <div class="card-stat-value">{report['analyzed_hosts']}</div>
                        <div class="card-stat-label">Hosts</div>
                    </div>
                    <div class="card-stat">
                        <div class="card-stat-value">{report['findings_count']}</div>
                        <div class="card-stat-label">Findings</div>
                    </div>
                </div>
            </a>
"""
    
    if reports:
        html_content += "        </div>\n"
    
    html_content += """
    </div>
</body>
</html>
"""
    
    # Write index.html
    index_path = os.path.join(directory, 'index.html')
    with open(index_path, 'w') as f:
        f.write(html_content)
    

@cli.command()
def report_incident():
    """Generate NIS2 Article 23 incident report (CSIRT early warning)."""
    from .incident import IncidentReporter
    reporter = IncidentReporter()
    reporter.run()

if __name__ == '__main__':
    cli()

