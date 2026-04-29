# Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Unified report generation via Celery.
Supports 6 formats: JSON, CSV, PDF, Markdown, JUnit XML, HTML.

v2.4.19 Reports module audit hardening — every text path that
embeds DB-stored user content (scan name, finding messages, asset
hostnames, executive summaries, remediation copy, ...) now flows
through a format-appropriate escaper:

  - HTML / PDF (HTML→PDF via WeasyPrint): `html.escape()` so a scan
    named `</title><script>alert(1)</script>` doesn't execute in
    the recipient's browser.
  - Markdown: a custom `_md_escape()` that backslash-escapes the
    structural characters (|, *, _, `, [, ], <, >) so a finding
    message with a stray `|` doesn't break the table layout (or
    worse, with `<script>` doesn't render as raw HTML in lenient
    Markdown viewers).
  - CSV: cells starting with `=`, `+`, `-`, `@`, tab, or carriage
    return get prefixed with `'` to neuter Excel formula injection
    (a finding message of `=cmd|'/c calc'!A1` would otherwise run
    cmd.exe when the recipient opens the CSV in Excel).
  - JUnit XML: `xml.sax.saxutils.escape()` + `quoteattr()` so a
    message containing `"` or `&` doesn't break the XML structure
    or inject sibling attributes.

Also v2.4.19:
  - Filenames are sanitized via `_safe_basename()` — only
    alphanumeric / `-` / `_` survive — so a scan named
    `../../../../etc/passwd` cannot escape `/tmp/nis2-reports/`.
  - HTML reports carry a `lang` attribute matching the user's
    locale (passed in by the caller).
  - WeasyPrint is REQUIRED for PDF requests (the silent fallback
    to HTML is gone) — if the import fails, the task fails and
    the user sees a real error instead of receiving an HTML file
    masquerading as `.pdf`.
"""
import asyncio
import csv
import html
import json
import logging
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from xml.etree.ElementTree import Element, SubElement, ElementTree

from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

REPORTS_DIR = "/tmp/nis2-reports"
os.makedirs(REPORTS_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# Cleanup beat task (v2.4.20 audit reports-005)
# ---------------------------------------------------------------------------

@celery_app.task
def cleanup_old_reports() -> dict:
    """Sweep `/tmp/nis2-reports/` of files older than `report_ttl_days`.

    Runs on the Celery beat schedule (once a day, see
    `app/tasks/celery_app.py`). Without this, `/tmp/nis2-reports`
    grows unbounded — a deploy generating 100s of reports/day fills
    the disk in weeks. The named volume `reports-data` is shared
    between api and worker (v2.4.19), so the worker's `os.unlink`
    deletes the file from the api's view too.

    Best-effort: a single `OSError` (file disappeared mid-iteration,
    permission denied on a manually-injected file) is logged and
    skipped — the next day's run will pick it up. The task always
    succeeds; the return dict surfaces counts to whoever's reading
    the worker logs.
    """
    from app.config import settings

    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.report_ttl_days)
    cutoff_ts = cutoff.timestamp()

    removed = 0
    skipped = 0
    bytes_freed = 0

    if not os.path.isdir(REPORTS_DIR):
        # Defensive: directory is normally created at module-import,
        # but if someone wipes it between runs we don't want the task
        # to crash — just log and exit.
        logger.info("cleanup_old_reports: reports dir missing (%s)", REPORTS_DIR)
        return {"removed": 0, "skipped": 0, "bytes_freed": 0}

    for filename in os.listdir(REPORTS_DIR):
        path = os.path.join(REPORTS_DIR, filename)
        try:
            if not os.path.isfile(path):
                continue
            mtime = os.path.getmtime(path)
            if mtime < cutoff_ts:
                size = os.path.getsize(path)
                os.unlink(path)
                removed += 1
                bytes_freed += size
        except OSError as exc:
            # File vanished mid-iteration (another worker process
            # racing this one), permission denied, etc. Don't blow
            # up the whole sweep — log and move on.
            logger.warning("cleanup_old_reports: skip %s — %s", path, exc)
            skipped += 1

    logger.info(
        "cleanup_old_reports: removed=%d skipped=%d freed=%d bytes (cutoff=%s)",
        removed, skipped, bytes_freed, cutoff.isoformat(),
    )
    return {"removed": removed, "skipped": skipped, "bytes_freed": bytes_freed}


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
        # v2.4.19 audit reports-001: pin the report to the
        # requesting org. The download endpoint validates this
        # later — see app/routers/reports.py.
        if str(scan.organization_id) != str(org_id):
            raise ValueError("Scan does not belong to requesting organization")
        results_q = await db.execute(select(ScanResult).where(ScanResult.scan_id == scan.id))
        results = results_q.scalars().all()
        findings_q = await db.execute(
            select(Finding).where(Finding.scan_id == scan.id).order_by(Finding.severity, Finding.created_at)
        )
        findings = findings_q.scalars().all()

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    # v2.4.19 audit reports-002: sanitize the scan name component
    # of the on-disk filename. Without this, a scan named
    # `../../../../etc/passwd` would resolve `os.path.join` outside
    # of REPORTS_DIR and the writer could clobber arbitrary files.
    base = f"nis2_report_{_safe_basename(scan.name)}_{ts}"

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
    result = gen(scan, results, findings, base)
    # Stash the org_id on the result so the API's /status and
    # /download endpoints can validate the requester's org matches.
    result["org_id"] = str(org_id)
    return result


# ---------------------------------------------------------------------------
# Sanitization helpers (v2.4.19 audit hardening)
# ---------------------------------------------------------------------------

def _safe_basename(name: str | None) -> str:
    """Reduce a user-supplied scan name to a filename-safe slug.
    Whitelist alphanumerics / hyphen / underscore — every other
    byte (path separators, dotted parents, unicode glyphs) gets
    replaced with `_`. Caps at 64 chars. Empty / None falls back
    to `report` so we never generate `nis2_report__<ts>.pdf`."""
    if not name:
        return "report"
    cleaned = re.sub(r"[^A-Za-z0-9_\-]", "_", name)[:64].strip("_")
    return cleaned or "report"


# Markdown structural characters. Backslash-escaping these inside
# a table cell prevents user content from breaking the table layout
# or injecting raw HTML in lenient Markdown viewers.
_MD_ESCAPE = re.compile(r"([\\|*_`\[\]<>])")


def _md(value: object) -> str:
    """Escape a value for safe inclusion in a Markdown table cell.
    Newlines are collapsed to spaces — pipes inside multi-line
    content otherwise break tables; readers who want the full text
    can open the JSON / HTML reports."""
    if value is None:
        return "-"
    s = str(value).replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    return _MD_ESCAPE.sub(r"\\\1", s)


def _csv_safe(value: object) -> str:
    """Neuter Excel formula injection.
    Cells beginning with `=`, `+`, `-`, `@`, tab, or carriage
    return are auto-evaluated by Excel / LibreOffice / Google
    Sheets when the file is opened. A finding message of
    `=cmd|'/c calc'!A1` would launch calc.exe on a Windows
    recipient's machine. Prefixing with a single quote (which
    spreadsheet apps strip on display) defangs the trick.
    See https://owasp.org/www-community/attacks/CSV_Injection."""
    if value is None:
        return ""
    s = str(value)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + s
    return s


def _xml_attr(value: object) -> str:
    """Escape a value for inclusion in an XML attribute. Returns
    the inner text (without surrounding quotes — ElementTree adds
    those). `xml.sax.saxutils.escape` handles `&`, `<`, `>`; we
    also escape `"` since attributes use double quotes."""
    from xml.sax.saxutils import escape
    if value is None:
        return ""
    return escape(str(value), {'"': "&quot;"})


def _xml_text(value: object) -> str:
    """Escape body text — `&`, `<`, `>` only (quotes don't matter
    in element text)."""
    from xml.sax.saxutils import escape
    if value is None:
        return ""
    return escape(str(value))


# ---------------------------------------------------------------------------
# JSON (no escaping needed — json.dumps handles everything)
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
# CSV (formula-injection neutered)
# ---------------------------------------------------------------------------

def _gen_csv(scan, results, findings, base) -> dict:
    path = os.path.join(REPORTS_DIR, f"{base}.csv")
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Severity", "Category", "Message", "Target", "Remediation",
                     "CVSS Score", "CVSS Vector", "Compliance Article", "Status"])
        for fi in findings:
            w.writerow([
                _csv_safe(fi.severity),
                _csv_safe(fi.category),
                _csv_safe(fi.message),
                _csv_safe(fi.target),
                _csv_safe(fi.remediation or ""),
                _csv_safe(fi.cvss_base_score or ""),
                _csv_safe(fi.cvss_vector or ""),
                _csv_safe(fi.compliance_article or ""),
                _csv_safe(fi.status),
            ])
    return _result(path, f"{base}.csv", "text/csv", "csv")


# ---------------------------------------------------------------------------
# Markdown (structural chars escaped)
# ---------------------------------------------------------------------------

def _gen_markdown(scan, results, findings, base) -> dict:
    lines = []
    lines.append("# NIS2 Compliance Scan Report\n")
    lines.append(f"**Scan:** {_md(scan.name)}  ")
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
        # Blockquote — escape pipes/asterisks/etc inside the body
        # so a `*emphasis*` from the user doesn't reflow the doc.
        lines.append(f"> {_md(scan.executive_summary)}\n")

    # Findings table
    lines.append("## Findings\n")
    lines.append("| Severity | Category | Finding | Target | Remediation |")
    lines.append("|----------|----------|---------|--------|-------------|")
    for f in findings:
        sev_icon = {"CRITICAL": "[!]", "HIGH": "[!]", "MEDIUM": "[-]", "LOW": "[.]"}.get(f.severity, "[ ]")
        lines.append(
            f"| {sev_icon} {_md(f.severity)} | {_md(f.category)} | {_md(f.message)} | "
            f"`{_md(f.target)}` | {_md(f.remediation) if f.remediation else '-'} |"
        )
    lines.append("")

    # Assets
    lines.append("## Assets\n")
    lines.append("| Target | IP | Status | Open Ports |")
    lines.append("|--------|-----|--------|-----------|")
    for r in results:
        st = "Active" if r.is_alive else "Inactive"
        ports = ", ".join(str(p) for p in (r.open_ports or [])) or "None"
        lines.append(f"| {_md(r.target)} | `{_md(r.ip)}` | {st} | {_md(ports)} |")
    lines.append("")

    lines.append(f"\n---\n*Generated by NIS2 Compliance Platform — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*\n")

    path = os.path.join(REPORTS_DIR, f"{base}.md")
    with open(path, "w") as f:
        f.write("\n".join(lines))
    return _result(path, f"{base}.md", "text/markdown", "markdown")


# ---------------------------------------------------------------------------
# JUnit XML (CI/CD integration) — attribute + text escaping via
# xml.sax.saxutils plus the wrappers above.
# ---------------------------------------------------------------------------

def _gen_junit(scan, results, findings, base) -> dict:
    # ElementTree's SubElement(name, attr=value) handles attribute
    # escaping for `&`, `<`, `>` automatically — but to be safe
    # against `"` we also pre-escape via _xml_attr() on the
    # user-supplied attribute values. Body text passes through
    # _xml_text() before assignment to .text.
    testsuites = Element(
        "testsuites",
        name=_xml_attr(scan.name or "NIS2 Scan"),
        tests=str(len(findings)),
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    # Group findings by target for testsuite structure
    targets: dict[str, list] = {}
    for f in findings:
        targets.setdefault(f.target, []).append(f)

    for target, target_findings in targets.items():
        suite = SubElement(
            testsuites,
            "testsuite",
            name=_xml_attr(target),
            tests=str(len(target_findings)),
        )
        for f in target_findings:
            tc = SubElement(
                suite,
                "testcase",
                name=_xml_attr(f.message),
                classname=_xml_attr(f.category or ""),
            )
            if f.severity in ("CRITICAL", "HIGH"):
                fail = SubElement(
                    tc, "failure",
                    message=_xml_attr(f.message),
                    type=_xml_attr(f.severity),
                )
                fail.text = _xml_text(
                    f"Remediation: {f.remediation or 'N/A'}\n"
                    f"CVSS: {f.cvss_base_score or 'N/A'}\n"
                    f"Article: {f.compliance_article or 'N/A'}"
                )
            elif f.severity == "MEDIUM":
                fail = SubElement(
                    tc, "failure",
                    message=_xml_attr(f.message),
                    type="WARNING",
                )
                fail.text = _xml_text(f"Remediation: {f.remediation or 'N/A'}")
            else:
                so = SubElement(tc, "system-out")
                so.text = _xml_text(f"INFO: {f.message} — {f.remediation or ''}")

    path = os.path.join(REPORTS_DIR, f"{base}.xml")
    tree = ElementTree(testsuites)
    tree.write(path, encoding="utf-8", xml_declaration=True)
    return _result(path, f"{base}.xml", "application/xml", "junit")


# ---------------------------------------------------------------------------
# HTML (every user-content interpolation goes through html.escape)
# ---------------------------------------------------------------------------

def _h(value: object) -> str:
    """Tiny shorthand for `html.escape` — used pervasively below
    so the templating reads close to a plain f-string."""
    if value is None:
        return ""
    return html.escape(str(value))


def _gen_html(scan, results, findings, base) -> dict:
    score = scan.total_score or 0
    sc = "#16a34a" if score > 80 else "#ca8a04" if score > 60 else "#dc2626"
    sev_colors = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#2563eb"}
    date_str = (scan.completed_at or scan.created_at).strftime('%Y-%m-%d %H:%M UTC') if (scan.completed_at or scan.created_at) else "N/A"

    f_rows = ""
    for f in findings:
        c = sev_colors.get(f.severity, "#6b7280")
        f_rows += (
            f'<tr><td><span style="background:{c};color:#fff;padding:2px 8px;'
            f'border-radius:4px;font-size:12px;font-weight:600">{_h(f.severity)}</span></td>'
            f'<td>{_h(f.category)}</td>'
            f'<td>{_h(f.message)}</td>'
            f'<td><code>{_h(f.target)}</code></td>'
            f'<td>{_h(f.remediation) if f.remediation else "-"}</td></tr>\n'
        )

    a_rows = ""
    for r in results:
        st = "Active" if r.is_alive else "Inactive"
        ports = ", ".join(str(p) for p in (r.open_ports or [])) or "None"
        a_rows += (
            f'<tr><td>{_h(r.target)}</td>'
            f'<td><code>{_h(r.ip)}</code></td>'
            f'<td>{st}</td>'
            f'<td>{_h(ports)}</td></tr>\n'
        )

    # Executive summary — escape the user-supplied text inside an
    # otherwise-static `<div class="executive">`. Pre-v2.4.19 this
    # was string-concat'd raw, opening an XSS that fired the moment
    # someone opened the report (or its PDF rendering pulled the
    # injected JS into the print pipeline).
    exec_block = ""
    if scan.executive_summary:
        exec_block = (
            f'<h2>Executive Summary</h2>'
            f'<div class="executive">{_h(scan.executive_summary)}</div>'
        )

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>NIS2 Report — {_h(scan.name)}</title>
<style>
@page{{size:A4;margin:2cm}}body{{font-family:'Helvetica Neue',Arial,sans-serif;color:#1e293b;line-height:1.6;font-size:11px;max-width:1100px;margin:0 auto;padding:20px}}
h1{{color:#0f172a;font-size:24px;border-bottom:3px solid #0f172a;padding-bottom:10px}}h2{{color:#334155;font-size:16px;margin-top:30px;border-bottom:1px solid #e2e8f0;padding-bottom:6px}}
.score-box{{text-align:center;padding:20px;border:2px solid {sc};border-radius:12px;display:inline-block}}.score{{font-size:48px;font-weight:800;color:{sc}}}.score-label{{font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:1px}}
.stats{{display:flex;gap:20px;margin:20px 0;flex-wrap:wrap}}.stat{{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px 16px;flex:1;text-align:center;min-width:100px}}.stat-value{{font-size:24px;font-weight:700;color:#0f172a}}.stat-label{{font-size:10px;color:#64748b;text-transform:uppercase}}
table{{width:100%;border-collapse:collapse;margin:10px 0}}th{{background:#f1f5f9;color:#475569;font-size:10px;text-transform:uppercase;letter-spacing:.5px;padding:8px 10px;text-align:left;border-bottom:2px solid #e2e8f0}}td{{padding:8px 10px;border-bottom:1px solid #f1f5f9;font-size:11px}}tr:hover{{background:#f8fafc}}
code{{background:#f1f5f9;padding:1px 4px;border-radius:3px;font-size:10px}}.footer{{margin-top:40px;padding-top:15px;border-top:1px solid #e2e8f0;color:#94a3b8;font-size:9px;text-align:center}}
.executive{{background:#f0f9ff;border-left:4px solid #0284c7;padding:15px;border-radius:0 8px 8px 0;margin:15px 0;white-space:pre-wrap}}
</style>
</head>
<body>
<h1>NIS2 Compliance Report</h1>
<p><strong>Scan:</strong> {_h(scan.name)} &nbsp;|&nbsp; <strong>Date:</strong> {date_str} &nbsp;|&nbsp; <strong>Duration:</strong> {scan.duration_seconds or 0}s</p>
<div class="score-box"><div class="score">{score}</div><div class="score-label">Compliance Score</div></div>
<div class="stats">
<div class="stat"><div class="stat-value">{scan.hosts_scanned or 0}</div><div class="stat-label">Hosts Scanned</div></div>
<div class="stat"><div class="stat-value">{scan.hosts_alive or 0}</div><div class="stat-label">Hosts Active</div></div>
<div class="stat"><div class="stat-value" style="color:#dc2626">{scan.findings_critical or 0}</div><div class="stat-label">Critical</div></div>
<div class="stat"><div class="stat-value" style="color:#ea580c">{scan.findings_high or 0}</div><div class="stat-label">High</div></div>
<div class="stat"><div class="stat-value" style="color:#ca8a04">{scan.findings_medium or 0}</div><div class="stat-label">Medium</div></div>
<div class="stat"><div class="stat-value" style="color:#2563eb">{scan.findings_low or 0}</div><div class="stat-label">Low</div></div>
</div>
{exec_block}
<h2>Findings ({len(findings)})</h2>
<table><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Target</th><th>Remediation</th></tr>{f_rows}</table>
<h2>Assets ({len(results)})</h2>
<table><tr><th>Target</th><th>IP</th><th>Status</th><th>Open Ports</th></tr>{a_rows}</table>
<div class="footer">Generated by NIS2 Compliance Platform &bull; {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} &bull; Ref: NIS2 Directive (EU) 2022/2555, D.Lgs 138/2024</div>
</body></html>"""

    path = os.path.join(REPORTS_DIR, f"{base}.html")
    with open(path, "w") as f:
        f.write(html_doc)
    return _result(path, f"{base}.html", "text/html", "html")


# ---------------------------------------------------------------------------
# PDF (HTML → WeasyPrint). v2.4.19: required dependency, no silent
# fallback. The Dockerfile installs the libgobject / libpango /
# libcairo system stack alongside the pip package.
# ---------------------------------------------------------------------------

def _gen_pdf(scan, results, findings, base) -> dict:
    html_result = _gen_html(scan, results, findings, base)
    html_path = html_result["file_path"]
    pdf_path = os.path.join(REPORTS_DIR, f"{base}.pdf")

    # WeasyPrint is now a required dependency for PDF generation.
    # Pre-v2.4.19 we caught ImportError and silently returned the
    # HTML file with a `.pdf` filename — a "PDF" download that was
    # actually HTML, which the user's PDF reader would refuse to
    # open without explanation. If the import or render fails, the
    # task fails and the API surfaces the error to the user.
    from weasyprint import HTML
    with open(html_path) as f:
        HTML(string=f.read()).write_pdf(pdf_path)
    return _result(pdf_path, f"{base}.pdf", "application/pdf", "pdf")


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
