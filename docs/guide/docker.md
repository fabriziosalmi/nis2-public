# Docker Guide

Complete guide for running NIS2 Scanner with Docker.

## Prerequisites

- Docker and Docker Compose installed
- Configuration file (e.g., `test_config.yaml`)

## Quick Start

### Minimal Stack (No Grafana)

```bash
docker-compose up -d
```

**Services:**
- Scanner (port 8000) - Serving HTML reports
- Prometheus (port 9090) - Metrics collection
- Node Exporter - Metrics exporter

### Full Stack (With Grafana)

```bash
docker-compose -f docker-compose.yml -f docker-compose.grafana.yml up -d
```

**Additional:**
- Grafana (port 3000) - Dashboard visualization

## Running Scans

### Basic Scan

```bash
docker-compose exec scanner python -m nis2scan.cli scan
```

### With Custom Config

```bash
CONFIG_FILE=./my_config.yaml docker-compose up -d
docker-compose exec scanner python -m nis2scan.cli scan
```

### With Profile

```bash
docker-compose exec scanner python -m nis2scan.cli scan --profile production
```

## Viewing Results

### HTML Reports

Open in browser:
```
http://localhost:8000/
```

Or specific report:
```
http://localhost:8000/nis2_report_<timestamp>.html
```

### Grafana Dashboard

1. Open: `http://localhost:3000`
2. Login: `admin` / `admin`
3. Navigate to: **Dashboards → NIS2 Compliance Overview**

### Prometheus Metrics

Open: `http://localhost:9090`

Query examples:
```promql
nis2_compliance_score{profile="default"}
nis2_findings_total{profile="default"}
nis2_analyzed_hosts{profile="default"}
```

## Troubleshooting

### Metrics Not Appearing

```bash
# Check metrics file exists
docker-compose exec scanner ls -la /app/reports/nis2_metrics.prom

# Check Node Exporter can read it
docker-compose exec node-exporter cat /var/lib/node_exporter/textfile_collector/nis2_metrics.prom

# Restart Prometheus
docker-compose restart prometheus
```

### Reports Not Visible

```bash
# Check scanner logs
docker-compose logs scanner

# List reports
docker-compose exec scanner ls -la /app/reports/
```

### Container Won't Start

```bash
# Check logs
docker-compose logs

# Rebuild image
docker-compose build --no-cache

# Force recreate
docker-compose up -d --force-recreate
```

## Cleanup

### Stop Services

```bash
docker-compose down
```

### Remove Volumes

::: warning
This will delete Grafana data and dashboards
:::

```bash
docker-compose down -v
```

### Clean Everything

```bash
docker-compose down -v --rmi all
```

## Advanced Usage

### Using Existing Grafana

1. Start minimal stack:
   ```bash
   docker-compose up -d
   ```

2. Configure Prometheus datasource in your Grafana:
   - URL: `http://localhost:9090`
   - Access: Server

3. Import dashboard:
   - Upload `grafana/provisioning/dashboards/nis2-compliance.json`

### Scheduled Scans

Add to crontab:
```bash
# Daily scan at 2 AM
0 2 * * * cd /path/to/nis2-public && docker-compose exec -T scanner python -m nis2scan.cli scan
```

### Multiple Configurations

```bash
# Morning scan
CONFIG_FILE=./config_morning.yaml docker-compose up -d
docker-compose exec scanner python -m nis2scan.cli scan

# Evening scan
CONFIG_FILE=./config_evening.yaml docker-compose restart scanner
docker-compose exec scanner python -m nis2scan.cli scan
```

## Test Script

Full end-to-end test:

```bash
#!/bin/bash
# test-docker-stack.sh

echo "🚀 Starting Docker stack..."
docker-compose up -d

echo "⏳ Waiting for services..."
sleep 10

echo "🔍 Running scan..."
docker-compose exec -T scanner python -m nis2scan.cli scan

echo "📊 Checking metrics..."
docker-compose exec -T scanner cat /app/reports/nis2_metrics.prom

echo "✅ Stack is ready!"
echo "📄 Reports: http://localhost:8000"
echo "🎯 Prometheus: http://localhost:9090"
```

Make executable:
```bash
chmod +x test-docker-stack.sh
./test-docker-stack.sh
```

## Next Steps

- [Configuration Guide](/guide/configuration) - Customize your scans
- [Deployment Options](/guide/deployment) - Production setups
- [Examples](/examples/) - Real-world scenarios
