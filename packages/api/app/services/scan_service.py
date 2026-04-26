# Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import logging
from typing import Any

from nis2scan.compliance import ComplianceEngine, ComplianceReport
from nis2scan.config import Config, Targets
from nis2scan.scanner import ScanResult, Scanner

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
        # Build Config from the stored snapshot
        targets = Targets(
            ip_ranges=config_snapshot.get("ip_ranges", []),
            domains=config_snapshot.get("domains", []),
            asns=config_snapshot.get("asns", []),
        )
        config = Config(
            targets=targets,
            project_name=config_snapshot.get("name", "NIS2 Scan"),
            scan_timeout=config_snapshot.get("scan_timeout", 10),
            concurrency=config_snapshot.get("concurrency", 20),
            features=config_snapshot.get(
                "features",
                {
                    "dns_checks": True,
                    "web_checks": True,
                    "port_scan": True,
                    "whois_checks": True,
                },
            ),
            max_hosts=config_snapshot.get("max_hosts", 100),
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
