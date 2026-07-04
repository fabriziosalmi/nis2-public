# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
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

from celery.signals import task_postrun

from app.tasks.celery_app import celery_app
from app.utils import report_dedup
from app.utils.report_i18n import t as _t, normalize_locale

logger = logging.getLogger(__name__)


# v2.4.22 audit reports-009: when the report task finishes
# (success OR failure), drop the inflight-dedup lock so a
# legitimate retry / regeneration isn't blocked for the full TTL.
#
# `task_postrun` fires for every task this Celery app handles, so
# we filter by sender name to limit the work to report tasks.
# Args layout matches the `generate_report_task(scan_id, org_id,
# format, locale)` signature; we match the FIRST 3 positionals.
# A best-effort .delete() — if Redis is down at that moment, the
# TTL eventually evicts the key.
@task_postrun.connect
def _clear_report_inflight_lock(
    sender=None, task_id=None, args=None, kwargs=None, **extra
):
    if sender is None or sender.name != "app.tasks.report_tasks.generate_report_task":
        return
    args = args or ()
    if len(args) < 3:
        # Defensive: shouldn't happen given the task signature,
        # but if a caller invents a different arity we don't want
        # to crash the postrun chain (which would silently break
        # other Celery instrumentation).
        return
    scan_id, org_id, fmt = str(args[0]), str(args[1]), str(args[2])
    try:
        report_dedup.clear_inflight_task(org_id, scan_id, fmt, task_id=task_id)
    except Exception as exc:
        # Belt-and-braces — the dedup helper already swallows
        # Redis failures, but if something further upstream
        # raises we don't want it to bring down task_postrun.
        logger.warning(
            "report-dedup: postrun clear failed for task %s: %s",
            task_id,
            exc,
        )


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

    for root, dirs, files in os.walk(REPORTS_DIR, topdown=False):
        for file in files:
            path = os.path.join(root, file)
            try:
                mtime = os.path.getmtime(path)
                if mtime < cutoff_ts:
                    size = os.path.getsize(path)
                    os.unlink(path)
                    removed += 1
                    bytes_freed += size
            except OSError as exc:
                # File vanished mid-iteration, permission denied, etc.
                logger.warning("cleanup_old_reports: skip %s — %s", path, exc)
                skipped += 1

        for d in dirs:
            dir_path = os.path.join(root, d)
            try:
                import uuid

                try:
                    uuid.UUID(d)
                    is_org_dir = True
                except ValueError:
                    is_org_dir = False

                if is_org_dir and not os.listdir(dir_path):
                    os.rmdir(dir_path)
            except OSError:
                pass

    logger.info(
        "cleanup_old_reports: removed=%d skipped=%d freed=%d bytes (cutoff=%s)",
        removed,
        skipped,
        bytes_freed,
        cutoff.isoformat(),
    )
    return {"removed": removed, "skipped": skipped, "bytes_freed": bytes_freed}


@celery_app.task(bind=True, max_retries=1, time_limit=120)
def generate_report_task(
    self,
    scan_id: str,
    org_id: str,
    format: str,
    locale: str | None = None,
):
    """Generate a compliance report in the requested format.

    v2.4.21: `locale` (default: caller's `user.locale`, normalised
    via `report_i18n.normalize_locale`) selects the language for
    document chrome (titles, table headers, footer). The default
    `None` keeps backwards compatibility with any in-flight task
    queued from a v2.4.20 client — falls through to English.
    """
    return asyncio.run(_generate_report(scan_id, org_id, format, locale))


async def _generate_report(
    scan_id: str,
    org_id: str,
    format: str,
    locale: str | None = None,
) -> dict:
    from app.database import async_session_factory, set_rls_org_context
    from app.models.scan import Scan
    from app.models.scan_result import ScanResult
    from app.models.finding import Finding
    from app.models.organization import Organization
    from sqlalchemy import select

    async with async_session_factory() as db:
        # H5: the worker has no request context, so scope this session to the
        # requesting org before any tenant-scoped read. No-op under the current
        # superuser role; required once the app role is NOSUPERUSER NOBYPASSRLS.
        await set_rls_org_context(db, org_id)
        scan = await db.get(Scan, uuid.UUID(scan_id))
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")
        # v2.4.19 audit reports-001: pin the report to the
        # requesting org. The download endpoint validates this
        # later — see app/routers/reports.py.
        if str(scan.organization_id) != str(org_id):
            raise ValueError("Scan does not belong to requesting organization")
        results_q = await db.execute(
            select(ScanResult).where(ScanResult.scan_id == scan.id)
        )
        results = results_q.scalars().all()
        findings_q = await db.execute(
            select(Finding)
            .where(Finding.scan_id == scan.id)
            .order_by(Finding.severity, Finding.created_at)
        )
        findings = findings_q.scalars().all()
        # Org display name for the report cover (PDF/HTML only).
        org = await db.get(Organization, scan.organization_id)
        org_name = org.name if org else None

        # v2.5.18: the report is a full NIS2 dossier, not just a scan dump.
        # Pull the org-scoped governance / incident / supply-chain / BIA data
        # while the session is open and flatten to plain dicts (the format
        # renderers run after the session closes). PDF/HTML only.
        nis2_ctx: dict | None = None
        if format in ("pdf", "html"):
            from app.routers.governance import GovernanceItem
            from app.models.incident import Incident
            from app.models.vendor import Vendor
            from app.models.bia import BusinessProcess

            oid = scan.organization_id
            gov = (await db.execute(
                select(GovernanceItem).where(GovernanceItem.organization_id == oid)
                .order_by(GovernanceItem.sort_order)
            )).scalars().all()
            incs = (await db.execute(
                select(Incident).where(Incident.organization_id == oid)
                .order_by(Incident.detected_at.desc())
            )).scalars().all()
            vends = (await db.execute(
                select(Vendor).where(Vendor.organization_id == oid)
                .order_by(Vendor.criticality, Vendor.name)
            )).scalars().all()
            procs = (await db.execute(
                select(BusinessProcess).where(BusinessProcess.organization_id == oid)
                .order_by(BusinessProcess.criticality_level, BusinessProcess.name)
            )).scalars().all()
            nis2_ctx = {
                "governance": [
                    {"item_id": g.item_id, "title": g.title, "priority": g.priority,
                     "status": g.status, "ref": g.nis2_reference} for g in gov
                ],
                "incidents": [
                    {"title": i.title, "type": i.incident_type, "severity": i.severity,
                     "status": i.status, "detected": i.detected_at,
                     "notif_deadline": i.notification_deadline} for i in incs
                ],
                "vendors": [
                    {"name": v.name, "criticality": v.criticality, "type": v.vendor_type,
                     "access": v.data_access_level, "score": v.security_score,
                     "art18": v.acn_rilevanza_art18} for v in vends
                ],
                "bia": [
                    {"name": p.name, "crit": p.criticality_level, "rto": p.rto_hours,
                     "rpo": p.rpo_hours, "mtpd": p.mtpd_hours, "bcp": p.has_bcp,
                     "drp": p.has_drp, "essential": p.acn_servizio_essenziale} for p in procs
                ],
            }

    # Create the org-specific directory first to make sure it exists
    org_reports_dir = os.path.join(REPORTS_DIR, str(org_id))
    os.makedirs(org_reports_dir, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    # v2.4.19 audit reports-002: sanitize the scan name component
    # of the on-disk filename. Without this, a scan named
    # `../../../../etc/passwd` would resolve `os.path.join` outside
    # of REPORTS_DIR and the writer could clobber arbitrary files.
    base = f"{org_id}/nis2_report_{_safe_basename(scan.name)}_{ts}"

    # Normalise the locale once, here, so every renderer downstream
    # gets the same canonical 2-letter code. Unknown / null falls
    # back to "en" — see `report_i18n.normalize_locale` for the
    # full fallback semantics.
    loc = normalize_locale(locale)

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
        raise ValueError(
            f"Unsupported format: {format}. Supported: {', '.join(generators.keys())}"
        )
    if format in ("pdf", "html"):
        result = gen(scan, results, findings, base, loc, org_name, nis2_ctx)
    else:
        result = gen(scan, results, findings, base, loc)
    # Stash the org_id on the result so the API's /status and
    # /download endpoints can validate the requester's org matches.
    result["org_id"] = str(org_id)
    # And the locale, useful for diagnostics ("did the user request
    # this in IT or did the worker default-fallback to EN?") without
    # parsing the file.
    result["locale"] = loc
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


def _gen_json(scan, results, findings, base, locale: str = "en") -> dict:
    # JSON is machine-readable; we don't translate field names (those
    # are part of the API contract — a downstream parser keys on
    # them). The locale tag is included as metadata so a consumer
    # who renders a localised UI on top of the JSON knows what
    # language any free-text fields it preserves came from.
    data = {
        "version": "2.2",
        "metadata": {
            "scan_id": str(scan.id),
            "scan_name": scan.name,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generator": "NIS2 Compliance Platform",
            "locale": locale,
        },
        "summary": {
            "total_score": scan.total_score,
            "hosts_scanned": scan.hosts_scanned,
            "hosts_alive": scan.hosts_alive,
            "findings_critical": scan.findings_critical,
            "findings_high": scan.findings_high,
            "findings_medium": scan.findings_medium,
            "findings_low": scan.findings_low,
        },
        "compliance_matrix": scan.compliance_matrix or {},
        "executive_summary": scan.executive_summary or "",
        "findings": [_finding_dict(f) for f in findings],
        "assets": [
            {
                "target": r.target,
                "ip": r.ip,
                "is_alive": r.is_alive,
                "open_ports": r.open_ports or [],
            }
            for r in results
        ],
    }
    path = os.path.join(REPORTS_DIR, f"{base}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    return _result(path, f"{base}.json", "application/json", "json")


# ---------------------------------------------------------------------------
# CSV (formula-injection neutered)
# ---------------------------------------------------------------------------


def _gen_csv(scan, results, findings, base, locale: str = "en") -> dict:
    path = os.path.join(REPORTS_DIR, f"{base}.csv")
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            [
                _t(locale, "h_severity"),
                _t(locale, "h_category"),
                _t(locale, "h_finding"),
                _t(locale, "h_target"),
                _t(locale, "h_remediation"),
                _t(locale, "h_cvss_score"),
                _t(locale, "h_cvss_vector"),
                _t(locale, "h_compliance_article"),
                _t(locale, "h_status"),
            ]
        )
        for fi in findings:
            w.writerow(
                [
                    _csv_safe(fi.severity),
                    _csv_safe(fi.category),
                    _csv_safe(fi.message),
                    _csv_safe(fi.target),
                    _csv_safe(fi.remediation or ""),
                    _csv_safe(fi.cvss_base_score or ""),
                    _csv_safe(fi.cvss_vector or ""),
                    _csv_safe(fi.compliance_article or ""),
                    _csv_safe(fi.status),
                ]
            )
    return _result(path, f"{base}.csv", "text/csv", "csv")


# ---------------------------------------------------------------------------
# Markdown (structural chars escaped)
# ---------------------------------------------------------------------------


def _gen_markdown(scan, results, findings, base, locale: str = "en") -> dict:
    lines = []
    lines.append(f"# {_t(locale, 'report_title')}\n")
    lines.append(f"**{_t(locale, 'field_scan')}:** {_md(scan.name)}  ")
    date_str = (
        (scan.completed_at or scan.created_at).strftime("%Y-%m-%d %H:%M UTC")
        if (scan.completed_at or scan.created_at)
        else _t(locale, "not_available")
    )
    lines.append(f"**{_t(locale, 'field_date')}:** {date_str}  ")
    lines.append(f"**{_t(locale, 'field_score')}:** {scan.total_score or 0}/100  ")
    lines.append(f"**{_t(locale, 'field_duration')}:** {scan.duration_seconds or 0}s\n")

    # Stats
    lines.append(f"## {_t(locale, 'summary')}\n")
    lines.append(f"| {_t(locale, 'metric')} | {_t(locale, 'value')} |")
    lines.append("|--------|-------|")
    lines.append(f"| {_t(locale, 'hosts_scanned')} | {scan.hosts_scanned or 0} |")
    lines.append(f"| {_t(locale, 'hosts_active')} | {scan.hosts_alive or 0} |")
    lines.append(f"| {_t(locale, 'critical')} | {scan.findings_critical or 0} |")
    lines.append(f"| {_t(locale, 'high')} | {scan.findings_high or 0} |")
    lines.append(f"| {_t(locale, 'medium')} | {scan.findings_medium or 0} |")
    lines.append(f"| {_t(locale, 'low')} | {scan.findings_low or 0} |")
    lines.append("")

    if scan.executive_summary:
        lines.append(f"## {_t(locale, 'executive_summary')}\n")
        # Blockquote — escape pipes/asterisks/etc inside the body
        # so a `*emphasis*` from the user doesn't reflow the doc.
        # executive_summary is HTML; strip tags to readable plain text for the
        # Markdown report (Markdown viewers don't reliably render embedded HTML,
        # and escaping it showed the raw tags). The inner text is still _md-escaped.
        _summary_text = html.unescape(re.sub(r"<[^>]+>", " ", scan.executive_summary))
        _summary_text = re.sub(r"\s+", " ", _summary_text).strip()
        lines.append(f"> {_md(_summary_text)}\n")

    # Findings table
    lines.append(f"## {_t(locale, 'findings')}\n")
    lines.append(
        f"| {_t(locale, 'h_severity')} | {_t(locale, 'h_category')} | "
        f"{_t(locale, 'h_finding')} | {_t(locale, 'h_target')} | "
        f"{_t(locale, 'h_remediation')} |"
    )
    lines.append("|----------|----------|---------|--------|-------------|")
    for f in findings:
        sev_icon = {
            "CRITICAL": "[!]",
            "HIGH": "[!]",
            "MEDIUM": "[-]",
            "LOW": "[.]",
        }.get(f.severity, "[ ]")
        lines.append(
            f"| {sev_icon} {_md(f.severity)} | {_md(f.category)} | {_md(f.message)} | "
            f"`{_md(f.target)}` | {_md(f.remediation) if f.remediation else _t(locale, 'not_applicable')} |"
        )
    lines.append("")

    # Assets
    lines.append(f"## {_t(locale, 'assets')}\n")
    lines.append(
        f"| {_t(locale, 'h_target')} | {_t(locale, 'h_ip')} | "
        f"{_t(locale, 'h_host_state')} | {_t(locale, 'h_open_ports')} |"
    )
    lines.append("|--------|-----|--------|-----------|")
    for r in results:
        st = _t(locale, "host_active") if r.is_alive else _t(locale, "host_inactive")
        ports = ", ".join(str(p) for p in (r.open_ports or [])) or _t(
            locale, "no_open_ports"
        )
        lines.append(f"| {_md(r.target)} | `{_md(r.ip)}` | {st} | {_md(ports)} |")
    lines.append("")

    lines.append(
        f"\n---\n*{_t(locale, 'generated_by_md')} — "
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*\n"
    )

    path = os.path.join(REPORTS_DIR, f"{base}.md")
    with open(path, "w") as f:
        f.write("\n".join(lines))
    return _result(path, f"{base}.md", "text/markdown", "markdown")


# ---------------------------------------------------------------------------
# JUnit XML (CI/CD integration) — attribute + text escaping via
# xml.sax.saxutils plus the wrappers above.
# ---------------------------------------------------------------------------


def _gen_junit(scan, results, findings, base, locale: str = "en") -> dict:
    # ElementTree's SubElement(name, attr=value) handles attribute
    # escaping for `&`, `<`, `>` automatically — but to be safe
    # against `"` we also pre-escape via _xml_attr() on the
    # user-supplied attribute values. Body text passes through
    # _xml_text() before assignment to .text.
    #
    # JUnit XML is consumed by CI pipelines (Jenkins, GitLab,
    # GitHub Actions test reporters) which expect English-ish field
    # names. We localise only the `failure type` attribute
    # (visible to engineers reading the test output) and the
    # body-text labels — the structural attribute names stay in
    # English so the XML stays parseable by the standard tooling.
    testsuites = Element(
        "testsuites",
        name=_xml_attr(scan.name or _t(locale, "report_title")),
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
                    tc,
                    "failure",
                    message=_xml_attr(f.message),
                    type=_xml_attr(f.severity),
                )
                fail.text = _xml_text(
                    f"{_t(locale, 'h_remediation')}: {f.remediation or _t(locale, 'not_available')}\n"
                    f"{_t(locale, 'h_cvss_score')}: {f.cvss_base_score or _t(locale, 'not_available')}\n"
                    f"{_t(locale, 'h_compliance_article')}: {f.compliance_article or _t(locale, 'not_available')}"
                )
            elif f.severity == "MEDIUM":
                fail = SubElement(
                    tc,
                    "failure",
                    message=_xml_attr(f.message),
                    type="WARNING",
                )
                fail.text = _xml_text(
                    f"{_t(locale, 'h_remediation')}: "
                    f"{f.remediation or _t(locale, 'not_available')}"
                )
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


# The scanner's SummaryGenerator decorates each regulation reference with a 📖
# link icon. WeasyPrint's PDF fonts have no emoji glyphs, so it renders as a
# tofu box in the PDF/HTML reports. Strip the icon-only reference anchors (the
# regulation references are already in the findings table) and any other stray
# emoji before embedding the executive summary. The web dashboard renders the
# summary separately and keeps the emoji.
_EMOJI_RE = re.compile(
    "[\U0001f000-\U0001faff\U00002600-\U000027bf\U00002b00-\U00002bff"
    "\U0001f1e6-\U0001f1ff\U0000fe00-\U0000fe0f]"
)


def _strip_report_emoji(value: str) -> str:
    # Drop the whole reference anchor first so no empty <a></a> is left behind.
    value = re.sub(r"<a\b[^>]*>\s*\U0001f4d6\s*</a>", "", value)
    return _EMOJI_RE.sub("", value)


def _matrix_pill(status: str) -> str:
    """Map a compliance-matrix coverage status to a pill colour class.

    The scanner emits free-text statuses (e.g. "Partially Automated (...)",
    "Manual Verification Required", "Automated (...)"). Default to the neutral
    "manual" (amber, needs-review) rather than green, so an unrecognised status
    never over-states compliance in a customer-facing document.
    """
    s = status.lower()
    if any(k in s for k in ("fail", "missing", "non-compliant", "not compliant", "not implemented")):
        return "gap"
    if "partial" in s:
        return "partial"
    if "manual" in s:
        return "manual"
    if any(k in s for k in ("automated", "verified", "compliant", "pass", "covered")):
        return "ok"
    return "manual"


# ---------------------------------------------------------------------------
# NIS2 dossier sections (v2.5.18): governance (Art.21) / incidents (Art.23) /
# supply chain (Art.18) / BIA. These turn the PDF from a scan dump into a full
# NIS2 conformity dossier. Labels are self-contained here (EN + IT, English
# fallback) so we don't touch report_i18n's five locale blocks; the section
# CONTENT is org data rendered as-is.
# ---------------------------------------------------------------------------

_NIS2_LABELS = {
    "en": {
        "sec_gov": "Governance Checklist — NIS2 Art. 21",
        "sec_inc": "Incident Register — NIS2 Art. 23",
        "sec_ven": "Supply Chain / Suppliers — NIS2 Art. 18",
        "sec_bia": "Business Impact Analysis (Continuity)",
        "h_item": "Item", "h_title": "Requirement", "h_priority": "Priority",
        "h_status": "Status", "h_ref": "Reference", "h_incident": "Incident",
        "h_type": "Type", "h_severity": "Severity", "h_detected": "Detected",
        "h_deadline": "72h deadline", "h_supplier": "Supplier",
        "h_criticality": "Criticality", "h_access": "Data access", "h_score": "Score",
        "h_process": "Process", "h_rto": "RTO", "h_rpo": "RPO", "h_mtpd": "MTPD",
        "h_continuity": "Continuity",
        "gov_summary": "{done}/{total} completed · weighted score {score}/100",
        "essential": "Essential",
        "st_done": "Done", "st_in_progress": "In progress",
        "st_not_started": "Not started", "st_not_applicable": "N/A",
        "cr1": "Critical", "cr2": "High", "cr3": "Medium", "cr4": "Low", "cr5": "Minimal",
        "posture": "NIS2 Posture at a Glance",
        "k_score": "Technical score", "k_gov": "Governance", "k_incidents": "Open incidents",
        "k_suppliers": "Art. 18 suppliers", "k_continuity": "BCP + DRP coverage",
        "legend": "Coverage", "leg_ok": "Automated", "leg_partial": "Partial",
        "leg_manual": "Manual check", "leg_gap": "Gap", "no_hosts": "No hosts responded to the scan.",
        "confidential": "Confidential — for the recipient organization only",
    },
    "it": {
        "sec_gov": "Checklist di Governance — NIS2 Art. 21",
        "sec_inc": "Registro Incidenti — NIS2 Art. 23",
        "sec_ven": "Catena di Fornitura / Fornitori — NIS2 Art. 18",
        "sec_bia": "Business Impact Analysis (Continuità)",
        "h_item": "Voce", "h_title": "Requisito", "h_priority": "Priorità",
        "h_status": "Stato", "h_ref": "Riferimento", "h_incident": "Incidente",
        "h_type": "Tipo", "h_severity": "Gravità", "h_detected": "Rilevato",
        "h_deadline": "Scadenza 72h", "h_supplier": "Fornitore",
        "h_criticality": "Criticità", "h_access": "Accesso dati", "h_score": "Punteggio",
        "h_process": "Processo", "h_rto": "RTO", "h_rpo": "RPO", "h_mtpd": "MTPD",
        "h_continuity": "Continuità",
        "gov_summary": "{done}/{total} completati · punteggio ponderato {score}/100",
        "essential": "Essenziale",
        "st_done": "Completato", "st_in_progress": "In corso",
        "st_not_started": "Non iniziato", "st_not_applicable": "N/A",
        "cr1": "Critico", "cr2": "Alto", "cr3": "Medio", "cr4": "Basso", "cr5": "Minimo",
        "posture": "Postura NIS2 in sintesi",
        "k_score": "Punteggio tecnico", "k_gov": "Governance", "k_incidents": "Incidenti aperti",
        "k_suppliers": "Fornitori Art. 18", "k_continuity": "Copertura BCP + DRP",
        "legend": "Copertura", "leg_ok": "Automatizzato", "leg_partial": "Parziale",
        "leg_manual": "Verifica manuale", "leg_gap": "Lacuna", "no_hosts": "Nessun host ha risposto alla scansione.",
        "confidential": "Riservato — solo per l'organizzazione destinataria",
    },
}


def _nl(locale: str | None, key: str) -> str:
    loc = locale if locale in _NIS2_LABELS else "en"
    return _NIS2_LABELS[loc].get(key) or _NIS2_LABELS["en"].get(key, key)


def _nis2_sections_html(ctx: dict | None, locale: str) -> str:
    """Render the governance / incident / supply-chain / BIA HTML blocks from
    the org-scoped context bundle built in `_generate_report`. Returns "" when
    there is nothing to show, so a bare scan report is unchanged."""
    if not ctx:
        return ""

    sev_colors = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#2563eb"}
    prio_colors = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04"}
    crit_colors = {1: "#dc2626", 2: "#ea580c", 3: "#ca8a04", 4: "#2563eb", 5: "#2563eb"}

    def _dt(v) -> str:
        return v.strftime("%Y-%m-%d %H:%M") if v else "—"

    out = ""

    gov = ctx.get("governance") or []
    if gov:
        weights = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}
        tot = sum(weights.get(g["priority"], 1) for g in gov)
        earned = sum(weights.get(g["priority"], 1) for g in gov if g["status"] == "done")
        gscore = round(earned / tot * 100) if tot else 0
        gdone = sum(1 for g in gov if g["status"] == "done")
        rows = ""
        for g in gov:
            pc = prio_colors.get(g["priority"], "#6b7280")
            st_lbl = _nl(locale, "st_" + g["status"])
            rows += (
                f"<tr><td><code>{_h(g['item_id'])}</code></td>"
                f"<td>{_h(g['title'])}</td>"
                f'<td><span class="badge" style="background:{pc}">{_h(g["priority"])}</span></td>'
                f"<td>{_h(g['ref'])}</td><td>{_h(st_lbl)}</td></tr>\n"
            )
        summary = _nl(locale, "gov_summary").format(done=gdone, total=len(gov), score=gscore)
        out += (
            f'<h2>{_h(_nl(locale, "sec_gov"))}</h2>'
            f'<p style="color:#64748b;margin:0 0 8px;font-size:10.5px">{_h(summary)}</p>'
            f'<table><thead><tr><th>{_h(_nl(locale, "h_item"))}</th><th>{_h(_nl(locale, "h_title"))}</th>'
            f'<th>{_h(_nl(locale, "h_priority"))}</th><th>{_h(_nl(locale, "h_ref"))}</th>'
            f'<th>{_h(_nl(locale, "h_status"))}</th></tr></thead><tbody>{rows}</tbody></table>'
        )

    incs = ctx.get("incidents") or []
    if incs:
        rows = ""
        for i in incs:
            sev = (i["severity"] or "").upper()
            sc2 = sev_colors.get(sev, "#6b7280")
            rows += (
                f"<tr><td>{_h(i['title'])}</td><td>{_h(i['type'])}</td>"
                f'<td><span class="badge" style="background:{sc2}">{_h(sev)}</span></td>'
                f"<td>{_h(i['status'])}</td><td>{_h(_dt(i['detected']))}</td>"
                f"<td>{_h(_dt(i['notif_deadline']))}</td></tr>\n"
            )
        out += (
            f'<h2>{_h(_nl(locale, "sec_inc"))}</h2>'
            f'<table><thead><tr><th>{_h(_nl(locale, "h_incident"))}</th><th>{_h(_nl(locale, "h_type"))}</th>'
            f'<th>{_h(_nl(locale, "h_severity"))}</th><th>{_h(_nl(locale, "h_status"))}</th>'
            f'<th>{_h(_nl(locale, "h_detected"))}</th><th>{_h(_nl(locale, "h_deadline"))}</th></tr></thead><tbody>{rows}</tbody></table>'
        )

    vends = ctx.get("vendors") or []
    if vends:
        rows = ""
        for v in vends:
            cc = crit_colors.get(v["criticality"], "#6b7280")
            cr_lbl = _nl(locale, "cr" + str(v["criticality"]))
            art18 = ' <span class="pill ok">Art. 18</span>' if v["art18"] else ""
            score = v["score"] if v["score"] is not None else "—"
            rows += (
                f"<tr><td>{_h(v['name'])}{art18}</td>"
                f'<td><span class="badge" style="background:{cc}">{_h(cr_lbl)}</span></td>'
                f"<td>{_h(v['type'])}</td><td>{_h(v['access'])}</td><td>{_h(score)}</td></tr>\n"
            )
        out += (
            f'<h2>{_h(_nl(locale, "sec_ven"))}</h2>'
            f'<table><thead><tr><th>{_h(_nl(locale, "h_supplier"))}</th><th>{_h(_nl(locale, "h_criticality"))}</th>'
            f'<th>{_h(_nl(locale, "h_type"))}</th><th>{_h(_nl(locale, "h_access"))}</th>'
            f'<th>{_h(_nl(locale, "h_score"))}</th></tr></thead><tbody>{rows}</tbody></table>'
        )

    procs = ctx.get("bia") or []
    if procs:
        rows = ""
        for p in procs:
            cc = crit_colors.get(p["crit"], "#6b7280")
            cr_lbl = _nl(locale, "cr" + str(p["crit"]))
            ess = ' <span class="pill ok">' + _h(_nl(locale, "essential")) + "</span>" if p["essential"] else ""
            cont = ("BCP" if p["bcp"] else "—") + " / " + ("DRP" if p["drp"] else "—")
            hh = lambda x: f"{x}h" if x is not None else "—"  # noqa: E731
            rows += (
                f"<tr><td>{_h(p['name'])}{ess}</td>"
                f'<td><span class="badge" style="background:{cc}">{_h(cr_lbl)}</span></td>'
                f"<td>{_h(hh(p['rto']))}</td><td>{_h(hh(p['rpo']))}</td>"
                f"<td>{_h(hh(p['mtpd']))}</td><td>{_h(cont)}</td></tr>\n"
            )
        out += (
            f'<h2>{_h(_nl(locale, "sec_bia"))}</h2>'
            f'<table><thead><tr><th>{_h(_nl(locale, "h_process"))}</th><th>{_h(_nl(locale, "h_criticality"))}</th>'
            f'<th>{_h(_nl(locale, "h_rto"))}</th><th>{_h(_nl(locale, "h_rpo"))}</th>'
            f'<th>{_h(_nl(locale, "h_mtpd"))}</th><th>{_h(_nl(locale, "h_continuity"))}</th></tr></thead><tbody>{rows}</tbody></table>'
        )

    return out


def _score_color(v: float) -> str:
    return "#16a34a" if v > 80 else "#ca8a04" if v > 60 else "#dc2626"


def _svg_ring(pct: float, color: str, size: int = 92, stroke: int = 11) -> str:
    """A donut ring as inline SVG (WeasyPrint renders the arc reliably; the
    centred number is an HTML overlay in `_donut_html`, which is more robust
    across WeasyPrint's partial SVG-text support)."""
    import math

    pct = max(0.0, min(100.0, float(pct)))
    r = 50 - stroke / 2
    circ = 2 * math.pi * r
    dash = circ * pct / 100.0
    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 100 100">'
        f'<circle cx="50" cy="50" r="{r:.1f}" fill="none" stroke="#e6ebf2" stroke-width="{stroke}"/>'
        f'<circle cx="50" cy="50" r="{r:.1f}" fill="none" stroke="{color}" stroke-width="{stroke}" '
        f'stroke-linecap="round" stroke-dasharray="{dash:.2f} {circ - dash:.2f}" transform="rotate(-90 50 50)"/>'
        "</svg>"
    )


def _donut_html(pct: float, color: str, num, size: int = 82, numsize: int = 24) -> str:
    return (
        f'<div class="donut" style="width:{size}px;height:{size}px;line-height:{size}px">'
        f"{_svg_ring(pct, color, size)}"
        f'<div class="donut-num" style="color:{color};font-size:{numsize}px;line-height:{size}px">{_h(num)}</div>'
        "</div>"
    )


def _gov_score(gov: list) -> tuple[int, int, int]:
    weights = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}
    tot = sum(weights.get(g["priority"], 1) for g in gov)
    earned = sum(weights.get(g["priority"], 1) for g in gov if g["status"] == "done")
    score = round(earned / tot * 100) if tot else 0
    done = sum(1 for g in gov if g["status"] == "done")
    return done, len(gov), score


def _posture_hero(scan, ctx: dict | None, locale: str) -> str:
    """One-band executive KPI hero — the five NIS2 pillars at a glance. This is
    the page people screenshot / the closing beat of the demo video."""
    ctx = ctx or {}
    gov = ctx.get("governance") or []
    incs = ctx.get("incidents") or []
    vends = ctx.get("vendors") or []
    procs = ctx.get("bia") or []

    score = scan.total_score or 0
    _, _, gscore = _gov_score(gov)
    open_inc = sum(1 for i in incs if i.get("status") not in ("closed", "recovered"))
    art18 = sum(1 for v in vends if v.get("art18"))
    with_plans = sum(1 for p in procs if p.get("bcp") and p.get("drp"))
    cont = round(with_plans / len(procs) * 100) if procs else 0

    def tile(viz: str, label: str) -> str:
        return f'<div class="kpi">{viz}<div class="kpi-label">{_h(label)}</div></div>'

    inc_col = "#dc2626" if open_inc else "#16a34a"
    tiles = (
        tile(_donut_html(score, _score_color(score), score, 84, 25), _nl(locale, "k_score"))
        + tile(_donut_html(gscore, _score_color(gscore), gscore, 84, 25), _nl(locale, "k_gov"))
        + tile(f'<div class="kpi-num" style="color:{inc_col}">{open_inc}</div>', _nl(locale, "k_incidents"))
        + tile(f'<div class="kpi-num" style="color:#0284c7">{art18}</div>', _nl(locale, "k_suppliers"))
        + tile(_donut_html(cont, _score_color(cont), f"{cont}%", 84, 21), _nl(locale, "k_continuity"))
    )
    return (
        f'<div class="hero avoid"><div class="hero-title">{_h(_nl(locale, "posture"))}</div>'
        f'<div class="kpis">{tiles}</div></div>'
    )


def _matrix_heatmap(cm: dict, locale: str) -> str:
    """Art. 21(2) a–j coverage as a colour strip + legend, above the detail table."""
    if not (isinstance(cm, dict) and cm):
        return ""
    colors = {"ok": "#16a34a", "partial": "#2563eb", "manual": "#ca8a04", "gap": "#dc2626"}
    cells = ""
    for measure in sorted(cm.keys()):
        val = cm[measure]
        status = str(val.get("status", "")) if isinstance(val, dict) else str(val)
        col = colors.get(_matrix_pill(status), "#94a3b8")
        letter = measure.split("_")[-1]
        cells += f'<div class="heat-cell" style="background:{col}">{_h(letter)}</div>'
    legs = ""
    for cls, key in (("ok", "leg_ok"), ("partial", "leg_partial"), ("manual", "leg_manual"), ("gap", "leg_gap")):
        legs += f'<span class="leg"><span class="sw" style="background:{colors[cls]}"></span>{_h(_nl(locale, key))}</span>'
    return f'<div class="heat">{cells}</div><div class="legend">{legs}</div>'


def _gen_html(scan, results, findings, base, locale: str = "en", org_name: str | None = None, nis2_ctx: dict | None = None) -> dict:
    score = scan.total_score or 0
    sc = "#16a34a" if score > 80 else "#ca8a04" if score > 60 else "#dc2626"
    sev_colors = {
        "CRITICAL": "#dc2626",
        "HIGH": "#ea580c",
        "MEDIUM": "#ca8a04",
        "LOW": "#2563eb",
    }
    date_str = (
        (scan.completed_at or scan.created_at).strftime("%Y-%m-%d %H:%M UTC")
        if (scan.completed_at or scan.created_at)
        else _t(locale, "not_available")
    )

    f_rows = ""
    for f in findings:
        c = sev_colors.get(f.severity, "#6b7280")
        f_rows += (
            f'<tr><td><span class="badge" style="background:{c}">{_h(f.severity)}</span></td>'
            f"<td>{_h(f.category)}</td>"
            f"<td>{_h(f.message)}</td>"
            f"<td><code>{_h(f.target)}</code></td>"
            f"<td>{_h(f.remediation) if f.remediation else '—'}</td></tr>\n"
        )

    a_rows = ""
    for r in results:
        st = _t(locale, "host_active") if r.is_alive else _t(locale, "host_inactive")
        ports = ", ".join(str(p) for p in (r.open_ports or [])) or _t(
            locale, "no_open_ports"
        )
        a_rows += (
            f"<tr><td>{_h(r.target)}</td>"
            f"<td><code>{_h(r.ip)}</code></td>"
            f"<td>{_h(st)}</td>"
            f"<td>{_h(ports)}</td></tr>\n"
        )
    if not a_rows:
        # Empty-state row instead of a bare header with no body (which reads
        # as a broken table in the customer-facing PDF).
        a_rows = (
            f'<tr><td colspan="4" style="text-align:center;color:#94a3b8;'
            f'padding:14px 10px">{_h(_nl(locale, "no_hosts"))}</td></tr>'
        )

    # Executive summary — RENDERED, not escaped. The scanner's SummaryGenerator
    # emits HTML (<div>/<strong>/<a>/<ul>…); html.escape()'ing it here showed the
    # raw tags verbatim instead of the formatted summary. It is safe to render
    # because SummaryGenerator now html-escapes every DATA value it interpolates
    # (risk names, finding text, references) at the source, so the only HTML left
    # is its own static structural tags. (Pre-v2.4.19 this was raw AND the data
    # was unescaped — THAT was the XSS; escaping the data at the source closes it,
    # without flattening the formatting.)
    exec_block = ""
    if scan.executive_summary:
        exec_block = (
            f"<h2>{_h(_t(locale, 'executive_summary'))}</h2>"
            f'<div class="executive">{_strip_report_emoji(scan.executive_summary)}</div>'
        )

    # Compliance matrix — the NIS2 Art. 21(2) measures (a–j) mapped to their
    # coverage status. Turns the report from a findings list into a conformity
    # document. The status text is scanner-generated (English); the column
    # chrome is localised.
    cm = scan.compliance_matrix or {}
    cm_block = ""
    if isinstance(cm, dict) and cm:
        cm_rows = ""
        for measure in sorted(cm.keys()):
            # Each value is either a plain status string or a
            # {"status": ..., "description": ...} object (the richer
            # scanner/seed format). Render the human description as the
            # measure name and the status text in the pill — never the
            # raw dict repr, which pre-v2.5.18 leaked "{'status': ...}"
            # into the customer-facing PDF.
            val = cm[measure]
            if isinstance(val, dict):
                status = str(val.get("status", "")).strip() or "—"
                desc = str(val.get("description", "")).strip()
            else:
                status = str(val)
                desc = ""
            letter = measure.split("_")[-1]
            name = desc or measure
            cm_rows += (
                f'<tr><td><strong>{_h(letter)})</strong>&nbsp; {_h(name)}</td>'
                f'<td><span class="pill {_matrix_pill(status)}">{_h(status)}</span></td></tr>\n'
            )
        cm_block = (
            f'<h2>{_h(_t(locale, "compliance_matrix"))}</h2>'
            f"{_matrix_heatmap(cm, locale)}"
            f'<table class="matrix"><thead><tr><th>{_h(_t(locale, "h_measure"))}</th>'
            f'<th>{_h(_t(locale, "h_coverage"))}</th></tr></thead><tbody>{cm_rows}</tbody></table>'
        )

    # Optional organisation line on the cover (only when we resolved the name).
    org_line = (
        f'<strong>{_h(_t(locale, "field_organization"))}:</strong> '
        f"{_h(org_name)} &nbsp;&bull;&nbsp; "
        if org_name
        else ""
    )

    # The lang attribute matches the user's requested locale (audit
    # reports-007). Browsers, screen-readers, and accessibility
    # tooling all key off this — pre-v2.4.21 it was hardcoded
    # `lang="en"` regardless of the report's actual content language.
    html_doc = f"""<!DOCTYPE html>
<html lang="{locale}">
<head>
<meta charset="utf-8">
<title>{_h(_t(locale, "html_title_prefix"))} — {_h(scan.name)}</title>
<style>
@page{{size:A4;margin:2.3cm 1.8cm 1.9cm;
  @top-right{{content:"{_h(_t(locale, 'report_title_h1'))}";font-size:7.5px;color:#cbd5e1;letter-spacing:.4px}}
  @bottom-left{{content:"{_h(_t(locale, 'footer_generated_by'))}";font-size:7.5px;color:#94a3b8}}
  @bottom-center{{content:"{_h(date_str)}";font-size:7.5px;color:#cbd5e1}}
  @bottom-right{{content:counter(page) " / " counter(pages);font-size:7.5px;color:#94a3b8}}
}}
:root{{--ink:#0f172a;--slate:#334155;--muted:#64748b;--primary:#0284c7;--line:#e2e8f0;--text-muted:#64748b}}
*{{box-sizing:border-box}}
body{{font-family:'Helvetica Neue',Arial,sans-serif;color:var(--slate);line-height:1.55;font-size:11px;margin:0}}
.cover{{border-bottom:3px solid var(--ink);padding-bottom:13px;margin-bottom:2px}}
.eyebrow{{font-size:9px;letter-spacing:2px;text-transform:uppercase;color:var(--primary);font-weight:700}}
h1{{color:var(--ink);font-size:25px;margin:5px 0 9px;font-weight:800;letter-spacing:-.4px}}
.cover-meta{{font-size:10px;color:var(--muted)}}.cover-meta strong{{color:var(--slate);font-weight:600}}
h2{{color:var(--ink);font-size:15px;margin:22px 0 9px;padding-bottom:6px;border-bottom:1px solid var(--line);font-weight:700;break-after:avoid}}
thead{{display:table-header-group}}
tr,td,th{{break-inside:avoid}}
.avoid{{break-inside:avoid}}
.confidential{{margin-top:7px;font-size:8px;letter-spacing:.4px;text-transform:uppercase;color:#94a3b8}}
.topgrid{{display:flex;gap:16px;margin:16px 0 4px;align-items:center}}
.score-box{{text-align:center;padding:10px 16px;border:2px solid {sc};border-radius:14px;display:flex;flex-direction:column;align-items:center;justify-content:center}}
.score-label{{font-size:8.5px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-top:6px}}
.statgrid{{display:flex;gap:8px;flex:1}}
.stat{{background:#f8fafc;border:1px solid var(--line);border-radius:8px;padding:9px 4px;flex:1;text-align:center}}
.stat-value{{font-size:20px;font-weight:700;color:var(--ink)}}.stat-label{{font-size:7.5px;color:var(--muted);text-transform:uppercase;letter-spacing:.3px;margin-top:2px}}
.donut{{position:relative;display:inline-block;text-align:center}}
.donut-num{{position:absolute;top:0;left:0;right:0;bottom:0;font-weight:800;text-align:center}}
.hero{{margin:14px 0 6px;padding:14px 16px 16px;background:#f8fafc;border:1px solid var(--line);border-radius:12px}}
.hero-title{{font-size:9px;letter-spacing:1.5px;text-transform:uppercase;color:var(--primary);font-weight:700;margin-bottom:10px}}
.kpis{{display:flex;gap:10px}}
.kpi{{flex:1;text-align:center}}
.kpi-num{{font-size:34px;font-weight:800;line-height:84px}}
.kpi-label{{font-size:8px;color:var(--muted);text-transform:uppercase;letter-spacing:.3px;margin-top:2px}}
.heat{{margin:4px 0 2px}}
.heat-cell{{display:inline-block;width:30px;height:30px;line-height:30px;text-align:center;border-radius:6px;color:#fff;font-weight:700;font-size:12px;margin-right:5px}}
.legend{{font-size:8.5px;color:var(--muted);margin:2px 0 6px}}.leg{{margin-right:12px}}.sw{{display:inline-block;width:9px;height:9px;border-radius:2px;vertical-align:middle;margin-right:3px}}
table{{width:100%;border-collapse:collapse;margin:8px 0}}
th{{background:#f1f5f9;color:#475569;font-size:9px;text-transform:uppercase;letter-spacing:.5px;padding:7px 10px;text-align:left;border-bottom:2px solid var(--line)}}
td{{padding:7px 10px;border-bottom:1px solid #f1f5f9;font-size:10.5px;vertical-align:top}}
code{{background:#f1f5f9;padding:1px 5px;border-radius:3px;font-size:9.5px;color:var(--slate)}}
.badge{{display:inline-block;padding:2px 9px;border-radius:999px;font-size:9px;font-weight:700;color:#fff;letter-spacing:.3px}}
.pill{{display:inline-block;padding:2px 9px;border-radius:999px;font-size:9px;font-weight:600}}
.pill.ok{{background:#dcfce7;color:#166534}}.pill.partial{{background:#dbeafe;color:#1e40af}}.pill.manual{{background:#fef9c3;color:#854d0e}}.pill.gap{{background:#fee2e2;color:#991b1b}}
.matrix td:first-child{{font-weight:600;color:var(--slate)}}
.executive{{background:#f0f9ff;border-left:4px solid var(--primary);padding:16px 20px;border-radius:0 8px 8px 0;margin:10px 0;font-size:11px}}
.executive p{{margin:0 0 10px}}.executive ul,.executive ol{{margin:6px 0 14px;padding-left:22px}}.executive li{{margin:0 0 6px;line-height:1.55}}.executive strong{{font-weight:700}}.executive a{{text-decoration:none}}
</style>
</head>
<body>
<div class="cover">
<div class="eyebrow">NIS2 Compliance Platform</div>
<h1>{_h(_t(locale, "report_title_h1"))}</h1>
<div class="cover-meta">{org_line}<strong>{_h(_t(locale, "field_scan"))}:</strong> {_h(scan.name)} &nbsp;&bull;&nbsp; <strong>{_h(_t(locale, "field_date"))}:</strong> {_h(date_str)} &nbsp;&bull;&nbsp; <strong>{_h(_t(locale, "field_duration"))}:</strong> {scan.duration_seconds or 0}s</div>
<div class="confidential">{_h(_nl(locale, "confidential"))}</div>
</div>
<div class="topgrid">
<div class="score-box">{_donut_html(score, sc, score, 104, 33)}<div class="score-label">{_h(_t(locale, "score_label"))}</div></div>
<div class="statgrid">
<div class="stat"><div class="stat-value">{scan.hosts_scanned or 0}</div><div class="stat-label">{_h(_t(locale, "hosts_scanned"))}</div></div>
<div class="stat"><div class="stat-value">{scan.hosts_alive or 0}</div><div class="stat-label">{_h(_t(locale, "hosts_active"))}</div></div>
<div class="stat"><div class="stat-value" style="color:#dc2626">{scan.findings_critical or 0}</div><div class="stat-label">{_h(_t(locale, "critical"))}</div></div>
<div class="stat"><div class="stat-value" style="color:#ea580c">{scan.findings_high or 0}</div><div class="stat-label">{_h(_t(locale, "high"))}</div></div>
<div class="stat"><div class="stat-value" style="color:#ca8a04">{scan.findings_medium or 0}</div><div class="stat-label">{_h(_t(locale, "medium"))}</div></div>
<div class="stat"><div class="stat-value" style="color:#2563eb">{scan.findings_low or 0}</div><div class="stat-label">{_h(_t(locale, "low"))}</div></div>
</div>
</div>
{_posture_hero(scan, nis2_ctx, locale)}
{exec_block}
{cm_block}
{_nis2_sections_html(nis2_ctx, locale)}
<h2>{_h(_t(locale, "findings"))} ({len(findings)})</h2>
<table><thead><tr><th>{_h(_t(locale, "h_severity"))}</th><th>{_h(_t(locale, "h_category"))}</th><th>{_h(_t(locale, "h_finding"))}</th><th>{_h(_t(locale, "h_target"))}</th><th>{_h(_t(locale, "h_remediation"))}</th></tr></thead><tbody>{f_rows}</tbody></table>
<h2>{_h(_t(locale, "assets"))} ({len(results)})</h2>
<table><thead><tr><th>{_h(_t(locale, "h_target"))}</th><th>{_h(_t(locale, "h_ip"))}</th><th>{_h(_t(locale, "h_host_state"))}</th><th>{_h(_t(locale, "h_open_ports"))}</th></tr></thead><tbody>{a_rows}</tbody></table>
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


def _gen_pdf(scan, results, findings, base, locale: str = "en", org_name: str | None = None, nis2_ctx: dict | None = None) -> dict:
    html_result = _gen_html(scan, results, findings, base, locale, org_name, nis2_ctx)
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
        "severity": f.severity,
        "category": f.category,
        "message": f.message,
        "target": f.target,
        "remediation": f.remediation,
        "cvss_base_score": f.cvss_base_score,
        "cvss_vector": f.cvss_vector,
        "compliance_article": f.compliance_article,
        "status": f.status,
    }


def _result(path, filename, content_type, fmt) -> dict:
    return {
        "file_path": path,
        "filename": os.path.basename(filename),
        "content_type": content_type,
        "size": os.path.getsize(path),
        "format": fmt,
    }
