# Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Unified report generation via Celery.
Supports 6 formats: JSON, CSV, PDF, Markdown, JUnit XML, HTML.
Ported from nis2_checker/report.py to the SaaS platform.
"""
import asyncio
import csv
import json
import os
import uuid
from datetime import datetime, timezone
from xml.etree.ElementTree import Element, SubElement, ElementTree

from app.tasks.celery_app import celery_app

REPORTS_DIR = "/tmp/nis2-reports"
os.makedirs(REPORTS_DIR, exist_ok=True)


@celery_app.task(bind=True, max_retries=1, time_limit=120)
def generate_report_task(self, scan_id: str, org_id: str, format: str):
    """Generate a compliance report in the requested format."""
    return asyncio.run(_generate_report(scan_id, org_id, format))


async def _generate_report(scan_id: str, org_id: str, format: str) -> dict:
    from app.database import async_session_factory
    from app.models.scan import Scan
    from app.models.scan_result import ScanResult
    from app.models.finding import Finding
    from sqlalchemy import select

    async with async_session_factory() as db:
        scan = await db.get(Scan, uuid.UUID(scan_id))
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")
        results_q = await db.execute(select(ScanResult).where(ScanResult.scan_id == scan.id))
        results = results_q.scalars().all()
        findings_q = await db.execute(
            select(Finding).where(Finding.scan_id == scan.id).order_by(Finding.severity, Finding.created_at)
        )
        findings = findings_q.scalars().all()

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base = f"nis2_report_{scan.name.replace(' ', '_')}_{ts}"

    generators = {
        "json": _gen_json,
        "csv": _gen_csv,
        "pdf": _gen_pdf,
        "markdown": _gen_markdown,
        "md": _gen_markdown,
        "junit": _gen_junit,
        "xml": _gen_junit,
        "html": _gen_html,
    }
    gen = generators.get(format)
    if not gen:
        raise ValueError(f"Unsupported format: {format}. Supported: {', '.join(generators.keys())}")
    return gen(scan, results, findings, base)


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def _gen_json(scan, results, findings, base) -> dict:
    data = {
        "version": "2.2",
        "metadata": {
            "scan_id": str(scan.id), "scan_name": scan.name,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generator": "NIS2 Compliance Platform",
        },
        "summary": {
            "total_score": scan.total_score,
            "hosts_scanned": scan.hosts_scanned, "hosts_alive": scan.hosts_alive,
            "findings_critical": scan.findings_critical, "findings_high": scan.findings_high,
            "findings_medium": scan.findings_medium, "findings_low": scan.findings_low,
        },
        "compliance_matrix": scan.compliance_matrix or {},
        "executive_summary": scan.executive_summary or "",
        "findings": [_finding_dict(f) for f in findings],
        "assets": [{"target": r.target, "ip": r.ip, "is_alive": r.is_alive, "open_ports": r.open_ports or []} for r in results],
    }
    path = os.path.join(REPORTS_DIR, f"{base}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    return _result(path, f"{base}.json", "application/json", "json")


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

def _gen_csv(scan, results, findings, base) -> dict:
    path = os.path.join(REPORTS_DIR, f"{base}.csv")
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Severity", "Category", "Message", "Target", "Remediation",
                     "CVSS Score", "CVSS Vector", "Compliance Article", "Status"])
        for fi in findings:
            w.writerow([fi.severity, fi.category, fi.message, fi.target,
                        fi.remediation or "", fi.cvss_base_score or "",
                        fi.cvss_vector or "", fi.compliance_article or "", fi.status])
    return _result(path, f"{base}.csv", "text/csv", "csv")


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def _gen_markdown(scan, results, findings, base) -> dict:
    lines = []
    lines.append("# NIS2 Compliance Scan Report\n")
    lines.append(f"**Scan:** {scan.name}  ")
    date_str = (scan.completed_at or scan.created_at).strftime('%Y-%m-%d %H:%M UTC') if (scan.completed_at or scan.created_at) else "N/A"
    lines.append(f"**Date:** {date_str}  ")
    lines.append(f"**Score:** {scan.total_score or 0}/100  ")
    lines.append(f"**Duration:** {scan.duration_seconds or 0}s\n")

    # Stats
    lines.append("## Summary\n")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Hosts Scanned | {scan.hosts_scanned or 0} |")
    lines.append(f"| Hosts Active | {scan.hosts_alive or 0} |")
    lines.append(f"| Critical | {scan.findings_critical or 0} |")
    lines.append(f"| High | {scan.findings_high or 0} |")
    lines.append(f"| Medium | {scan.findings_medium or 0} |")
    lines.append(f"| Low | {scan.findings_low or 0} |")
    lines.append("")

    if scan.executive_summary:
        lines.append("## Executive Summary\n")
        lines.append(f"> {scan.executive_summary}\n")

    # Findings table
    lines.append("## Findings\n")
    lines.append("| Severity | Category | Finding | Target | Remediation |")
    lines.append("|----------|----------|---------|--------|-------------|")
    for f in findings:
        sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(f.severity, "⚪")
        lines.append(f"| {sev_icon} {f.severity} | {f.category} | {f.message} | `{f.target}` | {f.remediation or '-'} |")
    lines.append("")

    # Assets
    lines.append("## Assets\n")
    lines.append("| Target | IP | Status | Open Ports |")
    lines.append("|--------|-----|--------|-----------|")
    for r in results:
        st = "✅ Active" if r.is_alive else "❌ Inactive"
        ports = ", ".join(str(p) for p in (r.open_ports or [])) or "None"
        lines.append(f"| {r.target} | `{r.ip}` | {st} | {ports} |")
    lines.append("")

    lines.append(f"\n---\n*Generated by NIS2 Compliance Platform — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*\n")

    path = os.path.join(REPORTS_DIR, f"{base}.md")
    with open(path, "w") as f:
        f.write("\n".join(lines))
    return _result(path, f"{base}.md", "text/markdown", "markdown")


# ---------------------------------------------------------------------------
# JUnit XML (CI/CD integration)
# ---------------------------------------------------------------------------

def _gen_junit(scan, results, findings, base) -> dict:
    testsuites = Element("testsuites", name=scan.name or "NIS2 Scan",
                         tests=str(len(findings)), timestamp=datetime.now(timezone.utc).isoformat())

    # Group findings by target for testsuite structure
    targets = {}
    for f in findings:
        targets.setdefault(f.target, []).append(f)

    for target, target_findings in targets.items():
        suite = SubElement(testsuites, "testsuite", name=target, tests=str(len(target_findings)))
        for f in target_findings:
            tc = SubElement(suite, "testcase", name=f.message, classname=f.category)
            if f.severity in ("CRITICAL", "HIGH"):
                fail = SubElement(tc, "failure", message=f.message, type=f.severity)
                fail.text = f"Remediation: {f.remediation or 'N/A'}\nCVSS: {f.cvss_base_score or 'N/A'}\nArticle: {f.compliance_article or 'N/A'}"
            elif f.severity == "MEDIUM":
                fail = SubElement(tc, "failure", message=f.message, type="WARNING")
                fail.text = f"Remediation: {f.remediation or 'N/A'}"
            else:
                so = SubElement(tc, "system-out")
                so.text = f"INFO: {f.message} — {f.remediation or ''}"

    path = os.path.join(REPORTS_DIR, f"{base}.xml")
    tree = ElementTree(testsuites)
    tree.write(path, encoding="utf-8", xml_declaration=True)
    return _result(path, f"{base}.xml", "application/xml", "junit")


# ---------------------------------------------------------------------------
# HTML (standalone, no dependencies)
# ---------------------------------------------------------------------------

def _gen_html(scan, results, findings, base) -> dict:
    score = scan.total_score or 0
    sc = "#16a34a" if score > 80 else "#ca8a04" if score > 60 else "#dc2626"
    sev_colors = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#2563eb"}
    date_str = (scan.completed_at or scan.created_at).strftime('%Y-%m-%d %H:%M UTC') if (scan.completed_at or scan.created_at) else "N/A"

    f_rows = ""
    for f in findings:
        c = sev_colors.get(f.severity, "#6b7280")
        f_rows += f'<tr><td><span style="background:{c};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600">{f.severity}</span></td><td>{f.category}</td><td>{f.message}</td><td><code>{f.target}</code></td><td>{f.remediation or "-"}</td></tr>\n'

    a_rows = ""
    for r in results:
        st = "Active" if r.is_alive else "Inactive"
        ports = ", ".join(str(p) for p in (r.open_ports or [])) or "None"
        a_rows += f'<tr><td>{r.target}</td><td><code>{r.ip}</code></td><td>{st}</td><td>{ports}</td></tr>\n'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>NIS2 Report — {scan.name}</title>
<style>
@page{{size:A4;margin:2cm}}body{{font-family:'Helvetica Neue',Arial,sans-serif;color:#1e293b;line-height:1.6;font-size:11px;max-width:1100px;margin:0 auto;padding:20px}}
h1{{color:#0f172a;font-size:24px;border-bottom:3px solid #0f172a;padding-bottom:10px}}h2{{color:#334155;font-size:16px;margin-top:30px;border-bottom:1px solid #e2e8f0;padding-bottom:6px}}
.score-box{{text-align:center;padding:20px;border:2px solid {sc};border-radius:12px;display:inline-block}}.score{{font-size:48px;font-weight:800;color:{sc}}}.score-label{{font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:1px}}
.stats{{display:flex;gap:20px;margin:20px 0;flex-wrap:wrap}}.stat{{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px 16px;flex:1;text-align:center;min-width:100px}}.stat-value{{font-size:24px;font-weight:700;color:#0f172a}}.stat-label{{font-size:10px;color:#64748b;text-transform:uppercase}}
table{{width:100%;border-collapse:collapse;margin:10px 0}}th{{background:#f1f5f9;color:#475569;font-size:10px;text-transform:uppercase;letter-spacing:.5px;padding:8px 10px;text-align:left;border-bottom:2px solid #e2e8f0}}td{{padding:8px 10px;border-bottom:1px solid #f1f5f9;font-size:11px}}tr:hover{{background:#f8fafc}}
code{{background:#f1f5f9;padding:1px 4px;border-radius:3px;font-size:10px}}.footer{{margin-top:40px;padding-top:15px;border-top:1px solid #e2e8f0;color:#94a3b8;font-size:9px;text-align:center}}
.executive{{background:#f0f9ff;border-left:4px solid #0284c7;padding:15px;border-radius:0 8px 8px 0;margin:15px 0}}
</style>
</head>
<body>
<h1>NIS2 Compliance Report</h1>
<p><strong>Scan:</strong> {scan.name} &nbsp;|&nbsp; <strong>Date:</strong> {date_str} &nbsp;|&nbsp; <strong>Duration:</strong> {scan.duration_seconds or 0}s</p>
<div class="score-box"><div class="score">{score}</div><div class="score-label">Compliance Score</div></div>
<div class="stats">
<div class="stat"><div class="stat-value">{scan.hosts_scanned or 0}</div><div class="stat-label">Hosts Scanned</div></div>
<div class="stat"><div class="stat-value">{scan.hosts_alive or 0}</div><div class="stat-label">Hosts Active</div></div>
<div class="stat"><div class="stat-value" style="color:#dc2626">{scan.findings_critical or 0}</div><div class="stat-label">Critical</div></div>
<div class="stat"><div class="stat-value" style="color:#ea580c">{scan.findings_high or 0}</div><div class="stat-label">High</div></div>
<div class="stat"><div class="stat-value" style="color:#ca8a04">{scan.findings_medium or 0}</div><div class="stat-label">Medium</div></div>
<div class="stat"><div class="stat-value" style="color:#2563eb">{scan.findings_low or 0}</div><div class="stat-label">Low</div></div>
</div>
{"<h2>Executive Summary</h2><div class='executive'>" + scan.executive_summary + "</div>" if scan.executive_summary else ""}
<h2>Findings ({len(findings)})</h2>
<table><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Target</th><th>Remediation</th></tr>{f_rows}</table>
<h2>Assets ({len(results)})</h2>
<table><tr><th>Target</th><th>IP</th><th>Status</th><th>Open Ports</th></tr>{a_rows}</table>
<div class="footer">Generated by NIS2 Compliance Platform &bull; {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} &bull; Ref: NIS2 Directive (EU) 2022/2555, D.Lgs 138/2024</div>
</body></html>"""

    path = os.path.join(REPORTS_DIR, f"{base}.html")
    with open(path, "w") as f:
        f.write(html)
    return _result(path, f"{base}.html", "text/html", "html")


# ---------------------------------------------------------------------------
# PDF (reuses HTML with WeasyPrint, fallback to HTML)
# ---------------------------------------------------------------------------

def _gen_pdf(scan, results, findings, base) -> dict:
    html_result = _gen_html(scan, results, findings, base)
    html_path = html_result["file_path"]

    pdf_path = os.path.join(REPORTS_DIR, f"{base}.pdf")
    try:
        from weasyprint import HTML
        with open(html_path) as f:
            HTML(string=f.read()).write_pdf(pdf_path)
        return _result(pdf_path, f"{base}.pdf", "application/pdf", "pdf")
    except ImportError:
        html_result["note"] = "PDF generation requires WeasyPrint. Falling back to HTML."
        return html_result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding_dict(f) -> dict:
    return {
        "severity": f.severity, "category": f.category, "message": f.message,
        "target": f.target, "remediation": f.remediation,
        "cvss_base_score": f.cvss_base_score, "cvss_vector": f.cvss_vector,
        "compliance_article": f.compliance_article, "status": f.status,
    }

def _result(path, filename, content_type, fmt) -> dict:
    return {"file_path": path, "filename": filename, "content_type": content_type,
            "size": os.path.getsize(path), "format": fmt}
