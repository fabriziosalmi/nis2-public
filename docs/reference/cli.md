# CLI Reference

Command-line interface reference for the NIS2 Scanner.

## Commands

### init

Interactively generate a configuration file.

```bash
python -m nis2scan.cli init [OPTIONS]
```

**Options**:

| Option | Short | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--output` | `-o` | PATH | `config.yaml` | Output configuration file path |

**Examples**:

```bash
# Create default config
python -m nis2scan.cli init

# Create custom config
python -m nis2scan.cli init -o my_scan.yaml
```

### clean

Remove all generated reports and evidence.

```bash
python -m nis2scan.cli clean [OPTIONS]
```

**Options**:

| Option | Short | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--force` | `-f` | FLAG | `False` | Force deletion without confirmation |

**Examples**:

```bash
# Interactive clean
python -m nis2scan.cli clean

# Force clean (no prompt)
python -m nis2scan.cli clean --force
```

### scan

Run a compliance scan.

```bash
python -m nis2scan.cli scan [OPTIONS]
```

**Options**:

| Option | Short | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--config` | `-c` | PATH | `config.yaml` | Configuration file path |
| `--profile` | `-p` | TEXT | `default` | Metrics profile name |
| `--output` | `-o` | PATH | `reports/` | Output directory |

**Examples**:

```bash
# Basic scan
python -m nis2scan.cli scan

# With custom config
python -m nis2scan.cli scan -c my_config.yaml

# With profile
python -m nis2scan.cli scan --profile production

# Custom output directory
python -m nis2scan.cli scan -o /tmp/reports/
```

### serve

Serve reports via HTTP.

```bash
python -m nis2scan.cli serve [OPTIONS]
```

**Options**:

| Option | Short | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--port` | `-p` | INTEGER | `8000` | Port to listen on |
| `--host` | `-h` | TEXT | `0.0.0.0` | Host to bind to |

**Examples**:

```bash
# Default (port 8000)
python -m nis2scan.cli serve

# Custom port
python -m nis2scan.cli serve --port 9000

# Localhost only
python -m nis2scan.cli serve --host 127.0.0.1
```

### report-incident

Generate NIS2 Article 23 incident report.

```bash
python -m nis2scan.cli report-incident [OPTIONS]
```

**Options**:

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `--title` | TEXT | Yes | Incident title |
| `--description` | TEXT | Yes | Incident description |
| `--severity` | CHOICE | Yes | Severity (low/medium/high/critical) |
| `--output` | PATH | No | Output file path |

**Examples**:

```bash
# Generate incident report
python -m nis2scan.cli report-incident \
  --title "Data Breach" \
  --description "Unauthorized access detected" \
  --severity critical \
  --output incident_report.pdf
```

## Docker Usage

### With docker-compose

```bash
# Scan
docker-compose exec scanner python -m nis2scan.cli scan

# Scan with config
docker-compose exec scanner python -m nis2scan.cli scan -c /app/configs/prod.yaml

# Serve (already running by default)
docker-compose exec scanner python -m nis2scan.cli serve --port 8000
```

### Standalone Docker

```bash
# Scan
docker run --rm \
  -v $(pwd)/config.yaml:/app/config.yaml:ro \
  -v $(pwd)/reports:/app/reports \
  nis2-scanner:latest \
  python -m nis2scan.cli scan

# Serve
docker run --rm -p 8000:8000 \
  -v $(pwd)/reports:/app/reports:ro \
  nis2-scanner:latest \
  python -m nis2scan.cli serve
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Configuration error |
| 3 | Scan error |
| 4 | Report generation error |

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CONFIG_FILE` | Default config file | `config.yaml` |
| `REPORTS_DIR` | Reports directory | `reports/` |
| `LOG_LEVEL` | Logging level | `INFO` |

**Example**:

```bash
export CONFIG_FILE=./prod_config.yaml
export LOG_LEVEL=DEBUG
python -m nis2scan.cli scan
```

## Output Files

### Reports

- `nis2_report_<timestamp>.html` - Interactive HTML report
- `nis2_report_<timestamp>.json` - Machine-readable JSON
- `nis2_report_<timestamp>.md` - Markdown report

### Evidence

- `scan_<timestamp>/verification_bundle_<timestamp>.zip` - Evidence bundle

### Metrics

- `nis2_metrics.prom` - Prometheus metrics

## Next Steps

- [Configuration Schema](/reference/config-schema) - Config file reference
- [Examples](/examples/) - Usage examples
- [Docker Guide](/guide/docker) - Docker deployment
