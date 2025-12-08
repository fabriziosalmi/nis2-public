import os
import time
from typing import Dict, Any, List
from prometheus_client import CollectorRegistry, Gauge, write_to_textfile
from .compliance import ComplianceReport

class PrometheusExporter:
    """
    Exports NIS2 compliance metrics to Prometheus format.
    Designed for Node Exporter Textfile Collector integration.
    """
    def __init__(self, registry: CollectorRegistry = None, profile_name: str = "default"):
        if registry is None:
            self.registry = CollectorRegistry()
        else:
            self.registry = registry
        
        self.profile = profile_name

        # Metric Definitions with standard labels
        self.compliance_score = Gauge(
            'nis2_compliance_score', 
            'Overall NIS2 Compliance Score (0-100)', 
            ['profile'],
            registry=self.registry
        )
        
        self.findings_total = Gauge(
            'nis2_findings_total', 
            'Total count of findings by severity', 
            ['severity', 'profile'],
            registry=self.registry
        )

        self.analyzed_hosts = Gauge(
            'nis2_analyzed_hosts',
            'Number of hosts successfully analyzed',
            ['profile'],
            registry=self.registry
        )

        self.last_scan_timestamp = Gauge(
            'nis2_last_scan_timestamp_seconds',
            'Unix timestamp of the last successful scan',
            ['profile'],
            registry=self.registry
        )

    def update_metrics(self, report: ComplianceReport):
        """Updates internal metrics based on the report data."""
        
        # Update Score
        self.compliance_score.labels(profile=self.profile).set(report.total_score)
        
        # Update Host Count
        self.analyzed_hosts.labels(profile=self.profile).set(report.stats.get('analyzed_hosts', 0))
        
        # Update Findings Count
        # Reset counts for clean state if reusing instance
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        
        for f in report.findings:
            if f.severity in severity_counts:
                severity_counts[f.severity] += 1
            else:
                pass
        
        for sev, count in severity_counts.items():
            self.findings_total.labels(severity=sev, profile=self.profile).set(count)

        # Update Timestamp
        self.last_scan_timestamp.labels(profile=self.profile).set_to_current_time()

    def export_to_file(self, file_path: str):
        """Writes metrics to a .prom file for Node Exporter."""
        # Ensure directory exists
        directory = os.path.dirname(file_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
            
        write_to_textfile(file_path, self.registry)
