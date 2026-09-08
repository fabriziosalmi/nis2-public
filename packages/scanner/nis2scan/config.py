# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
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
    # Optional pre-resolved hostname -> IP map. When the API hands us a
    # scan config it embeds the IP it resolved at validation time so the
    # scanner connects to that exact address (DNS-rebinding mitigation).
    # CLI users without pre-resolution leave this empty and the scanner
    # falls back to live DNS lookup.
    pinned_ips: dict = field(default_factory=dict)
    allow_private_ips: bool = False

    # Keys this loader understands. An unknown key is a typo, and silently
    # ignoring it was the defect: `concurrancy: 200` in a YAML file was accepted
    # and the scan ran at the default 20, with no error and no warning. That
    # matters more than a normal config typo here, because these values govern
    # how hard the platform touches third-party infrastructure — concurrency and
    # max_hosts are the two settings an operator reaches for after a customer
    # complains about scan load, and both could be silently ignored.
    _KNOWN_KEYS = frozenset({
        "project_name", "scan_timeout", "concurrency", "targets",
        "compliance_profile", "max_hosts", "features", "pinned_ips",
        "allow_private_ips", "dry_run",
    })
    _KNOWN_TARGET_KEYS = frozenset({"ip_ranges", "domains", "asns"})

    # Same bounds the API enforces on the equivalent request fields, so a config
    # file cannot ask for something the HTTP surface would have rejected.
    _BOUNDS = {
        "concurrency": (1, 200),
        "scan_timeout": (1, 120),
        "max_hosts": (0, 100000),
    }

    @classmethod
    def load(cls, path: str, max_hosts: int = 0, dry_run: bool = False) -> "Config":
        with open(path, "r") as f:
            data = yaml.safe_load(f)

        if data is None:
            raise ValueError(f"{path} is empty.")
        if not isinstance(data, dict):
            raise ValueError(f"{path} must contain a mapping at the top level.")

        unknown = set(data) - cls._KNOWN_KEYS
        if unknown:
            raise ValueError(
                f"{path} has unrecognised key(s): {', '.join(sorted(unknown))}. "
                f"Known keys: {', '.join(sorted(cls._KNOWN_KEYS))}."
            )

        for key, (low, high) in cls._BOUNDS.items():
            if key not in data:
                continue
            value = data[key]
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError(f"{path}: {key} must be an integer, got {value!r}.")
            if not low <= value <= high:
                raise ValueError(
                    f"{path}: {key} must be between {low} and {high}, got {value}."
                )

        t_data = data.get('targets', {}) or {}
        if not isinstance(t_data, dict):
            raise ValueError(f"{path}: targets must be a mapping.")
        unknown_targets = set(t_data) - cls._KNOWN_TARGET_KEYS
        if unknown_targets:
            raise ValueError(
                f"{path}: targets has unrecognised key(s): "
                f"{', '.join(sorted(unknown_targets))}."
            )

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
            features=data.get('features', {}),
            pinned_ips=data.get('pinned_ips', {}),
            allow_private_ips=data.get('allow_private_ips', False),
        )

