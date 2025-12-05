# API Reference

## Scanner Module

### `Scanner` Class
The main class for orchestrating checks.

```python
from nis2_checker.scanner import Scanner

scanner = Scanner(config)
results = scanner.scan_target(target)
```

### `NmapScanner` Class
Handles infrastructure audits using Nmap.

```python
from nis2_checker.nmap_scanner import NmapScanner

nmap = NmapScanner(config)
results = nmap.scan_target(target)
```
