# Deployment Options

## Overview

The NIS2 Scanner offers flexible deployment options to match your needs - from quick scans to full monitoring setups.

## Quick Mode (Default)

Minimal stack for fast scans without visualization:

```bash
docker-compose up -d
```

**Services:**
- **Traefik** (ports 80/443) - Reverse Proxy & HTTPS
- **Scanner** (internal) - HTML report server
- **Prometheus** (port 9090) - Metrics collection
- **Node Exporter** - System metrics

**Best for:**
- Quick security scans
- CI/CD pipelines
- Minimal resource usage
- Development and testing

## Full Stack (With Grafana)

Complete monitoring setup with visualization:

```bash
docker-compose -f docker-compose.yml -f docker-compose.grafana.yml up -d
```

**Additional Services:**
- **Grafana** (port 3000) - Dashboard visualization

**Best for:**
- Long-term monitoring
- Visual dashboards
- Historical metrics analysis
- Production environments

## Using Existing Grafana

Integrate with your existing Grafana instance:

1. **Start minimal stack:**
   ```bash
   docker-compose up -d
   ```

2. **Configure Prometheus datasource in Grafana:**
   - URL: `http://localhost:9090` (or your Prometheus endpoint)
   - Access: Server (default)
   - Save & Test

3. **Import dashboard:**
   - Navigate to Dashboards → Import
   - Upload `grafana/provisioning/dashboards/nis2-compliance.json`

## Service Overview

| Service | Port | Required | Purpose |
|---------|------|----------|---------|
| Traefik | 80/443 | ✅ Yes | Reverse Proxy & HTTPS |
| Scanner | - | ✅ Yes | Serves HTML reports (internal) |
| Prometheus | 9090 | ✅ Yes | Metrics collection |
| Node Exporter | - | ✅ Yes | Exports metrics |
| Grafana | 3000 | ⚪ Optional | Visualization |

## Deployment Examples

### Quick Scan (No Visualization)

```bash
# Start services
docker-compose up -d

# Run scan
docker-compose exec scanner python -m nis2scan.cli scan

# View reports
open https://localhost
```

### Full Monitoring Setup

```bash
# Start with Grafana
docker-compose -f docker-compose.yml -f docker-compose.grafana.yml up -d

# Run scan
docker-compose exec scanner python -m nis2scan.cli scan

# View in Grafana
open http://localhost:3000
```

### Production Deployment

```bash
# Use production config
CONFIG_FILE=./config_prod.yaml \
docker-compose -f docker-compose.yml -f docker-compose.grafana.yml up -d

# Schedule regular scans (cron example)
0 2 * * * docker-compose exec -T scanner python -m nis2scan.cli scan
```

### CI/CD Integration

```yaml
# .github/workflows/security-scan.yml
name: NIS2 Security Scan

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Start Scanner
        run: |
          CONFIG_FILE=./config_prod.yaml docker-compose up -d
          
      - name: Run Scan
        run: |
          docker-compose exec -T scanner python -m nis2scan.cli scan
          
      - name: Upload Reports
        uses: actions/upload-artifact@v3
        with:
          name: nis2-reports
          path: reports/
```

## Enabling Grafana Permanently

To make Grafana part of the default stack, edit `docker-compose.yml`:

```yaml
# Uncomment these lines:
grafana:
  image: grafana/grafana:latest
  container_name: nis2-grafana
  volumes:
    - ./grafana/provisioning:/etc/grafana/provisioning
    - grafana-data:/var/lib/grafana
  environment:
    - GF_SECURITY_ADMIN_PASSWORD=admin
    - GF_USERS_ALLOW_SIGN_UP=false
  ports:
    - "3000:3000"
  depends_on:
    - prometheus
  networks:
    - nis2-net
```

And uncomment the volume:

```yaml
volumes:
  grafana-data:
```

## Resource Requirements

### Quick Mode
- **CPU**: 1 core
- **RAM**: 512 MB
- **Disk**: 1 GB

### Full Stack
- **CPU**: 2 cores
- **RAM**: 2 GB
- **Disk**: 5 GB (for Grafana data)

## Scaling Considerations

### Horizontal Scaling

Run multiple scanner instances:

```yaml
# docker-compose.scale.yml
services:
  scanner:
    deploy:
      replicas: 3
```

```bash
docker-compose -f docker-compose.yml -f docker-compose.scale.yml up -d
```

### Performance Tuning

Adjust concurrency in config:

```yaml
concurrency: 20  # Increase for faster scans
scan_timeout: 30  # Increase for thorough scans
```

## Cleanup

### Stop Services

```bash
docker-compose down
```

### Remove Volumes

```bash
# WARNING: This deletes Grafana data
docker-compose down -v
```

### Clean Everything

```bash
# Remove containers, networks, volumes, and images
docker-compose down -v --rmi all
```

## Next Steps

- [Configuration Guide](/guide/configuration) - Customize your scans
- [Troubleshooting](/guide/troubleshooting) - Common issues
- [Examples](/examples/) - Real-world scenarios
