from dataclasses import dataclass, field
import yaml
from typing import List

@dataclass
class Targets:
    ip_ranges: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    asns: List[str] = field(default_factory=list)

@dataclass
class Config:
    targets: Targets
    project_name: str = "NIS2 Scan"
    scan_timeout: int = 10
    concurrency: int = 20
    compliance_profile: str = "default"
    max_hosts: int = 0 # 0 means unlimited
    dry_run: bool = False
    features: dict = field(default_factory=dict)

    @classmethod
    def load(cls, path: str, max_hosts: int = 0, dry_run: bool = False) -> "Config":
        with open(path, "r") as f:
            data = yaml.safe_load(f)
        
        # Manual parsing/validation since we dropped Pydantic
        t_data = data.get('targets', {})
        targets = Targets(
            ip_ranges=t_data.get('ip_ranges', []),
            domains=t_data.get('domains', []),
            asns=t_data.get('asns', [])
        )
        
        # Determine max_hosts: CLI arg overrides config file if set (>0)
        # If CLI arg is 0 (default), try to use config file value
        # If config file is missing it, default to 0 (unlimited)
        final_max_hosts = max_hosts if max_hosts > 0 else data.get('max_hosts', 0)

        return cls(
            project_name=data.get('project_name', "NIS2 Scan"),
            scan_timeout=data.get('scan_timeout', 10),
            concurrency=data.get('concurrency', 20),
            targets=targets,
            compliance_profile=data.get('compliance_profile', 'default'),
            max_hosts=final_max_hosts,
            dry_run=dry_run,
            features=data.get('features', {})
        )
