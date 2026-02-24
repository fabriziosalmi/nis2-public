# API Reference

## ScannerLogic

The main orchestrator that coordinates all plugins and scanners for a given target.

```python
from nis2_checker.scanner_logic import ScannerLogic

scanner = ScannerLogic(config)
results = await scanner.scan_target(target)
```

`scan_target(target)` accepts a dict with either a `url` or `ip` key and returns a list of `TargetScanResult` objects. Targets with CIDR notation in `ip` are expanded via Nmap host discovery before scanning.

## Plugin Architecture

Scanners are implemented as plugins that subclass `ScannerPlugin` from `nis2_checker.plugins.base`. Each plugin implements the `scan(target, context)` coroutine and returns a list of `CheckResult` objects.

### Built-in Plugins

| Plugin | Module | Checks |
|---|---|---|
| `WebScannerPlugin` | `nis2_checker.plugins.web_plugin` | Connectivity, security headers, P.IVA, WAF/CDN detection |
| `CompliancePlugin` | `nis2_checker.plugins.compliance_plugin` | `security.txt` (RFC 9116) |
| `InfrastructurePlugin` | `nis2_checker.plugins.infrastructure_plugin` | SSL/TLS, SPF, DMARC |

### Writing a Custom Plugin

```python
from nis2_checker.plugins.base import ScannerPlugin
from nis2_checker.models import CheckResult, Severity
from typing import Dict, Any, List

class MyPlugin(ScannerPlugin):
    async def scan(self, target: Dict[str, Any], context: Dict[str, Any]) -> List[CheckResult]:
        # Perform checks and return results
        return []
```

Register the plugin by appending an instance to `ScannerLogic.plugins` after initialization.

## NmapScanner

Handles infrastructure audits using Nmap subprocesses. Used by `ScannerLogic` when `nmap.enabled` is `true` in `config.yaml`.

```python
from nis2_checker.nmap_scanner import NmapScanner

nmap = NmapScanner(config.get('nmap', {}))
results = nmap.scan_target(target)
```

## Data Models

### CheckResult

Represents the outcome of a single compliance check.

| Field | Type | Description |
|---|---|---|
| `check_id` | `str` | Unique identifier for the check (e.g. `ssl_tls`) |
| `name` | `str` | Human-readable check name |
| `status` | `str` | `PASS`, `FAIL`, `WARN`, or `SKIPPED` |
| `details` | `str` | Description of the result |
| `severity` | `Severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO` |
| `nis2_article` | `str` | Relevant NIS2 article reference |
| `remediation` | `str` | Suggested fix (only present on `FAIL`) |

### TargetScanResult

Aggregates all `CheckResult` objects for a single scan target.

| Field | Type | Description |
|---|---|---|
| `target` | `str` | URL or IP address of the scanned target |
| `name` | `str` | Human-readable target label |
| `timestamp` | `datetime` | Time the scan was performed |
| `compliance_score` | `float` | Weighted score from 0 to 100 |
| `results` | `List[CheckResult]` | All check results for this target |

Call `calculate_score()` to compute the weighted compliance score after populating `results`. Weights are: CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1, INFO=0.
