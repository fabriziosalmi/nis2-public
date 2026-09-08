# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import logging
from typing import Any

from nis2scan.compliance import ComplianceEngine, ComplianceReport
from nis2scan.config import Config, Targets
from nis2scan.scanner import ScanResult, Scanner

from app.schemas.scan import ScanConfigSnapshot

logger = logging.getLogger(__name__)


class ScanService:
    """Adapter between the NIS2 Platform API and the nis2scan scanner engine."""

    @staticmethod
    async def execute_scan(
        scan_id: str, config_snapshot: dict[str, Any], org_id: str
    ) -> tuple[list[ScanResult], ComplianceReport]:
        """Called by Celery task. Runs the scanner and compliance engine, returning
        raw results and a compliance report.

        The scanner and compliance engine code is used as-is from the nis2scan package.
        """
        # Validate the snapshot before trusting it.
        #
        # This used to be a sequence of .get() calls with a default for every
        # key, so a damaged or empty JSONB value produced empty target lists and
        # no error — the scan then probed nothing and was scored 100. Parsing
        # through the schema means a snapshot that does not describe at least one
        # target raises here, and the caller records the scan as failed with the
        # reason, instead of running a scan of nothing.
        cfg = ScanConfigSnapshot.model_validate(config_snapshot)

        targets = Targets(
            ip_ranges=cfg.ip_ranges,
            domains=cfg.domains,
            asns=config_snapshot.get("asns", []),
        )
        config = Config(
            targets=targets,
            project_name=cfg.name,
            scan_timeout=cfg.scan_timeout,
            concurrency=cfg.concurrency,
            features=cfg.features,
            max_hosts=cfg.max_hosts,
            pinned_ips=cfg.pinned_ips,
        )

        logger.info(
            "Starting scan %s for org %s with %d domains, %d IP ranges",
            scan_id,
            org_id,
            len(targets.domains),
            len(targets.ip_ranges),
        )

        # Run scanner (existing code unchanged)
        scanner = Scanner(config)
        results = await scanner.run()

        # Run compliance engine (existing code unchanged)
        engine = ComplianceEngine(config)
        report = engine.evaluate(results, scan_id=scan_id)

        logger.info(
            "Scan %s completed: score=%s, findings=%d",
            scan_id,
            report.total_score,
            len(report.findings),
        )

        return results, report
