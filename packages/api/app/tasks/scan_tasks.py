# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import asyncio
import hashlib
import logging
import uuid
from datetime import datetime, timezone

from app.tasks.celery_app import celery_app
from app.database import async_session_factory

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, max_retries=2, acks_late=True)
def run_scan_task(self, scan_id: str) -> dict:
    """Celery task that executes a scan asynchronously."""
    logger.info("Starting Celery task for scan %s", scan_id)
    try:
        result = asyncio.run(_run_scan(scan_id))
        return result
    except Exception as exc:
        logger.error("Scan task %s failed: %s", scan_id, exc)
        raise self.retry(exc=exc, countdown=30)


async def _run_scan(scan_id: str) -> dict:
    from app.models.finding import Finding
    from app.models.scan import Scan
    from app.models.scan_result import ScanResult as ScanResultModel
    from app.services.scan_service import ScanService

    async with async_session_factory() as db:
        # Load scan
        try:
            scan_uuid = uuid.UUID(scan_id)
        except (ValueError, AttributeError):
            logger.error("Invalid scan_id: %s", scan_id)
            return {"status": "error", "message": "Invalid scan ID"}
        scan = await db.get(Scan, scan_uuid)
        if not scan:
            logger.error("Scan %s not found", scan_id)
            return {"status": "error", "message": "Scan not found"}

        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        await db.commit()

        try:
            results, report = await ScanService.execute_scan(
                scan_id=str(scan.id),
                config_snapshot=scan.config_snapshot or {},
                org_id=str(scan.organization_id),
            )

            # Persist scan results
            for result in results:
                db_result = ScanResultModel(
                    scan_id=scan.id,
                    target=result.target,
                    ip=result.ip,
                    is_alive=result.is_alive,
                    open_ports=list(result.open_ports) if result.open_ports else [],
                    http_info=result.http_info or {},
                    tls_info=result.tls_info or {},
                    dns_info=getattr(result, "dns_info", {}) or {},
                    legal_info=getattr(result, "legal_info", {}) or {},
                    resilience_info=getattr(result, "resilience_info", {}) or {},
                    whois_info=getattr(result, "whois_info", {}) or {},
                    secrets_found=getattr(result, "secrets_found", []) or [],
                    errors=list(result.errors) if result.errors else [],
                )
                db.add(db_result)

            # Persist findings
            now = datetime.now(timezone.utc)
            for finding in report.findings:
                fingerprint = hashlib.sha256(
                    f"{finding.category}:{finding.message}:{getattr(finding, 'target', '')}".encode()
                ).hexdigest()

                db_finding = Finding(
                    scan_id=scan.id,
                    organization_id=scan.organization_id,
                    severity=finding.severity,
                    category=finding.category,
                    message=finding.message,
                    rationale=getattr(finding, "rationale", None),
                    target=getattr(finding, "target", ""),
                    reference=getattr(finding, "reference", None),
                    cvss_base_score=getattr(finding, "cvss_base_score", None),
                    cvss_vector=getattr(finding, "cvss_vector", None),
                    technical_detail=getattr(finding, "technical_detail", None),
                    remediation=getattr(finding, "remediation", None),
                    remediation_cost=getattr(finding, "remediation_cost", None),
                    remediation_effort=getattr(finding, "remediation_effort", None),
                    compliance_article=getattr(finding, "compliance_article", None),
                    fingerprint=fingerprint,
                    first_seen_at=now,
                    last_seen_at=now,
                )
                db.add(db_finding)

            # Update scan summary
            scan.status = "completed"
            scan.total_score = report.total_score
            scan.hosts_scanned = report.stats.get("analyzed_hosts", 0)
            scan.hosts_alive = report.stats.get("active_hosts", 0)
            scan.findings_critical = sum(
                1 for f in report.findings if f.severity == "CRITICAL"
            )
            scan.findings_high = sum(
                1 for f in report.findings if f.severity == "HIGH"
            )
            scan.findings_medium = sum(
                1 for f in report.findings if f.severity == "MEDIUM"
            )
            scan.findings_low = sum(
                1 for f in report.findings if f.severity == "LOW"
            )
            scan.compliance_matrix = getattr(report, "compliance_matrix", {})
            scan.executive_summary = getattr(report, "executive_summary", "")
            scan.completed_at = datetime.now(timezone.utc)
            if scan.started_at:
                scan.duration_seconds = int(
                    (scan.completed_at - scan.started_at).total_seconds()
                )

            await db.commit()

            logger.info(
                "Scan %s completed successfully: score=%s, findings=%d",
                scan_id,
                scan.total_score,
                len(report.findings),
            )

            return {
                "status": "completed",
                "scan_id": scan_id,
                "score": scan.total_score,
                "findings_count": len(report.findings),
            }

        except Exception as e:
            logger.error("Scan %s failed: %s", scan_id, e, exc_info=True)
            scan.status = "failed"
            scan.error_message = str(e)[:4096]
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()
            raise


@celery_app.task(bind=True)
def run_scheduled_scan_task(self, schedule_id: str):
    """Run a scan from a schedule definition."""
    asyncio.run(_run_scheduled_scan(schedule_id))


async def _run_scheduled_scan(schedule_id: str):
    from app.models.scan_schedule import ScanSchedule
    from app.models.asset import Asset
    from app.models.scan import Scan

    async with async_session_factory() as db:
        try:
            sched_uuid = uuid.UUID(schedule_id)
        except (ValueError, AttributeError):
            logger.error("Invalid schedule_id: %s", schedule_id)
            return
        schedule = await db.get(ScanSchedule, sched_uuid)
        if not schedule or not schedule.is_active:
            return

        config = schedule.config or {}
        asset_ids = config.get("asset_ids", [])

        # Resolve asset targets
        domains = []
        ip_ranges = []
        pinned_ips: dict[str, str] = {}
        if asset_ids:
            from sqlalchemy import select
            assets_result = await db.execute(
                select(Asset).where(
                    Asset.id.in_([uuid.UUID(a) for a in asset_ids]),
                    Asset.organization_id == schedule.organization_id,
                    Asset.is_active.is_(True),
                )
            )
            for asset in assets_result.scalars().all():
                if asset.target_type == "domain":
                    domains.append(asset.target_value)
                    # P2-05 audit fix: forward the validation-time
                    # pinned IP so the scanner connects to the exact
                    # address resolved at asset-creation time, closing
                    # the DNS-rebinding TOCTOU window. This mirrors
                    # the manual scan flow in routers/scans.py.
                    if asset.pinned_ip:
                        pinned_ips[asset.target_value] = asset.pinned_ip
                elif asset.target_type in ("ip", "cidr"):
                    ip_ranges.append(asset.target_value)

        if not domains and not ip_ranges:
            return

        # Create scan record
        scan = Scan(
            organization_id=schedule.organization_id,
            created_by=schedule.created_by,
            name=f"{schedule.name} - {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')}",
            scan_type=config.get("scan_type", "full"),
            config_snapshot={
                "name": schedule.name,
                "domains": domains,
                "ip_ranges": ip_ranges,
                "pinned_ips": pinned_ips,
                "features": config.get("features", {}),
                "concurrency": config.get("concurrency", 20),
                "scan_timeout": config.get("scan_timeout", 10),
                "max_hosts": config.get("max_hosts", 0),
            },
            status="pending",
        )
        db.add(scan)
        await db.flush()

        # Update schedule
        schedule.last_run_at = datetime.now(timezone.utc)
        await db.commit()

    # Run the scan
    await _run_scan(str(scan.id))


@celery_app.task
def check_scheduled_scans():
    """Celery Beat task: check for due scheduled scans and trigger them."""
    asyncio.run(_check_schedules())


async def _check_schedules():
    from app.models.scan_schedule import ScanSchedule
    from sqlalchemy import select

    async with async_session_factory() as db:
        result = await db.execute(
            select(ScanSchedule).where(ScanSchedule.is_active.is_(True))
        )
        schedules = result.scalars().all()

        now = datetime.now(timezone.utc)
        for schedule in schedules:
            if _should_run(schedule.cron_expression, schedule.last_run_at, now):
                run_scheduled_scan_task.delay(str(schedule.id))


def _should_run(cron_expr: str, last_run, now) -> bool:
    """Simple cron check: returns True if the schedule is due."""
    try:
        parts = cron_expr.strip().split()
        if len(parts) != 5:
            return False

        minute, hour, dom, month, dow = parts

        def matches(field, value):
            if field == "*":
                return True
            # Handle comma-separated lists: "1,3,5"
            if "," in field:
                return any(matches(part.strip(), value) for part in field.split(","))
            # Handle step: "*/5" or "1-10/2"
            if "/" in field:
                base, step = field.split("/", 1)
                step = int(step)
                if base == "*":
                    return value % step == 0
                elif "-" in base:
                    low, high = base.split("-", 1)
                    return int(low) <= value <= int(high) and (value - int(low)) % step == 0
                else:
                    start = int(base)
                    return value >= start and (value - start) % step == 0
            # Handle range: "1-5"
            if "-" in field:
                low, high = field.split("-", 1)
                return int(low) <= value <= int(high)
            # Exact match
            return str(value) == field

        if not all([
            matches(minute, now.minute),
            matches(hour, now.hour),
            matches(dom, now.day),
            matches(month, now.month),
            matches(dow, now.isoweekday() % 7),  # 0=Sun
        ]):
            return False

        # Don't run if already ran this minute
        if last_run and (now - last_run).total_seconds() < 60:
            return False

        return True
    except Exception as exc:
        # Pre-2.4.27 this swallowed the exception silently and the
        # schedule simply never fired — the exact "looks valid, doesn't
        # work" failure mode v2.4.26 fixed at the API/input layer. Now
        # we log so the operator running celery-beat sees WHY a schedule
        # didn't trigger, even for rows that pre-date the input
        # validator (e.g. legacy "@daily" / "MON" entries that the
        # parser still cannot handle). Stays at WARNING because beat
        # iterates every minute over every schedule — ERROR would spam
        # the log if a single bad row exists.
        logger.warning(
            "Cron parse failed for schedule (expr=%r): %s — schedule will not fire",
            cron_expr,
            exc,
        )
        return False
