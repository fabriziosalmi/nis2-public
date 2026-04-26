# DEPRECATED — Legacy Scanner Module

> **This directory (`nis2_checker/`) is deprecated and maintained for backward compatibility only.**
> 
> All active development has moved to the SaaS platform under `packages/`.

## What replaced it

| Legacy (`nis2_checker/`) | New Location (`packages/`) |
|--------------------------|---------------------------|
| `scanner_logic.py` | `packages/scanner/nis2scan/scanner.py` |
| `compliance_scanner.py` | `packages/scanner/nis2scan/compliance.py` |
| `report.py` | `packages/api/app/tasks/report_tasks.py` |
| `incident_reporter.py` | `packages/api/app/routers/incidents.py` |
| `governance_engine.py` | `packages/api/app/routers/governance.py` |
| `web.py` (FastAPI + Jinja2) | `packages/web/` (Next.js 15) |
| `database.py` (SQLite) | `packages/api/app/database.py` (PostgreSQL) |
| `nmap_scanner.py` | `packages/scanner/nis2scan/scanner.py` (integrated) |

## Migration guide

If you're using the CLI scanner directly:

```bash
# OLD (deprecated)
python -m nis2_checker.main --config config.yaml --targets targets.yaml

# NEW (SaaS platform)
make dev                          # Start full stack
open http://localhost:8077         # Web UI
curl http://localhost:8000/docs    # API docs
```

## When will this be removed?

This directory will be removed in a future major version (v3.0.0). Until then, it remains functional but receives no new features.
