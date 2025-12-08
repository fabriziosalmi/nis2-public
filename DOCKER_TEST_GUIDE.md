# NIS2 Scanner - Docker Stack Quick Test Guide

## Prerequisites
- Docker and Docker Compose installed
- `test_config.yaml` configured with target domain

## Quick Start (Without Grafana)
```bash
docker-compose up -d
```

This starts the minimal stack:
- **Scanner** (port 8000) - Serving HTML reports
- **Prometheus** (port 9090) - Metrics collection
- **Node Exporter** - Metrics exporter

## Full Stack (With Grafana)
If you want Grafana dashboards, use:
```bash
docker-compose -f docker-compose.yml -f docker-compose.grafana.yml up -d
```

This adds:
- **Grafana** (port 3000) - Dashboard visualization

### Using Existing Grafana
If you already have a Grafana instance, just use the quick start and configure Prometheus as a datasource in your existing Grafana:
- Prometheus URL: `http://localhost:9090` (or your Prometheus endpoint)

## Step 2: Run a Scan Inside Docker
```bash
docker-compose exec scanner python -m nis2scan.cli scan -c test_config.yaml --profile test
```

This will:
1. Scan the target in `test_config.yaml`
2. Generate HTML/JSON/Markdown reports in `reports/`
3. Export Prometheus metrics to `reports/nis2_metrics.prom`
4. Create evidence bundle

## Step 3: View HTML Report
Open in browser:
```
http://localhost:8000/nis2_report_<timestamp>.html
```

Or list all reports:
```
http://localhost:8000/
```

## Step 4: View Grafana Dashboard (Optional)
**Note**: Only available if you started with the full stack using `docker-compose.grafana.yml`

1. Open: `http://localhost:3000`
2. Login: `admin` / `admin` (or skip if auth disabled)
3. Navigate to: **Dashboards → NIS2 Compliance Overview**
4. Select profile: `test` from dropdown
5. Dashboard shows:
   - Compliance score gauge
   - Findings by severity (time series)

## Step 5: Verify Prometheus Metrics
Open: `http://localhost:9090`

Query examples:
```promql
nis2_compliance_score{profile="test"}
nis2_findings_total{profile="test"}
nis2_analyzed_hosts{profile="test"}
```

## Troubleshooting

### Metrics not appearing in Grafana?
```bash
# Check if metrics file exists
docker-compose exec scanner ls -la /app/reports/nis2_metrics.prom

# Check Node Exporter can read it
docker-compose exec node-exporter cat /var/lib/node_exporter/textfile_collector/nis2_metrics.prom

# Restart Prometheus to force scrape
docker-compose restart prometheus
```

### Reports not visible?
```bash
# Check Nginx is serving
docker-compose logs scanner

# List reports
docker-compose exec scanner ls -la /app/reports/
```

## Clean Up
```bash
# Stop stack
docker-compose down

# Remove volumes (WARNING: deletes Grafana data)
docker-compose down -v
```

## Full End-to-End Test Script
```bash
#!/bin/bash
# test-docker-stack.sh

echo "🚀 Starting Docker stack (quick mode - no Grafana)..."
docker-compose up -d

# For full stack with Grafana, use instead:
# docker-compose -f docker-compose.yml -f docker-compose.grafana.yml up -d

echo "⏳ Waiting for services to be ready..."
sleep 10

echo "🔍 Running scan..."
docker-compose exec -T scanner python -m nis2scan.cli scan -c test_config.yaml --profile test

echo "📊 Checking metrics..."
docker-compose exec -T scanner cat /app/reports/nis2_metrics.prom

echo "✅ Stack is ready!"
echo "📄 Reports: http://localhost:8000"
echo "📈 Grafana: http://localhost:3000"
echo "🎯 Prometheus: http://localhost:9090"
```

Make executable and run:
```bash
chmod +x test-docker-stack.sh
./test-docker-stack.sh
```
