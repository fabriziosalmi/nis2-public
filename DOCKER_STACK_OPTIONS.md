# Docker Compose Stack Options

## Quick Start (Recommended for Fast Scans)

Start the minimal stack without Grafana:

```bash
docker-compose up -d
```

**Includes:**
- NIS2 Scanner (port 8000) - HTML report server
- Prometheus (port 9090) - Metrics collection
- Node Exporter - System metrics

**Use when:**
- You want to run quick scans
- You don't need visualization dashboards
- You want minimal resource usage

## Full Stack (With Grafana)

Start with Grafana dashboards:

```bash
docker-compose -f docker-compose.yml -f docker-compose.grafana.yml up -d
```

**Adds:**
- Grafana (port 3000) - Dashboard visualization

**Use when:**
- You want visual dashboards
- You need historical metrics visualization
- You're setting up long-term monitoring

## Using Existing Grafana

If you already have a Grafana instance:

1. Use the quick start (without Grafana)
2. Configure Prometheus datasource in your existing Grafana:
   - URL: `http://localhost:9090` (or your Prometheus endpoint)
   - Access: Server (default)
3. Import the dashboard from `grafana/provisioning/dashboards/nis2-compliance.json`

## Enabling Grafana Permanently

To enable Grafana by default, uncomment the service in `docker-compose.yml`:

```yaml
# Uncomment these lines:
grafana:
  image: grafana/grafana:latest
  # ... rest of config
```

And uncomment the volume:

```yaml
volumes:
  grafana-data:
```

## Services Overview

| Service | Port | Required | Purpose |
|---------|------|----------|---------|
| Scanner | 8000 | ✅ Yes | Serves HTML reports |
| Prometheus | 9090 | ✅ Yes | Metrics collection |
| Node Exporter | - | ✅ Yes | Exports metrics |
| Grafana | 3000 | ⚪ Optional | Visualization |

## Examples

### Quick scan without visualization
```bash
docker-compose up -d
docker-compose exec scanner python -m nis2scan.cli scan
```

### Full monitoring setup
```bash
docker-compose -f docker-compose.yml -f docker-compose.grafana.yml up -d
docker-compose exec scanner python -m nis2scan.cli scan
# View in Grafana: http://localhost:3000
```

### Using existing Grafana
```bash
# Start minimal stack
docker-compose up -d

# In your existing Grafana:
# 1. Add Prometheus datasource: http://localhost:9090
# 2. Import dashboard from grafana/provisioning/dashboards/
```
