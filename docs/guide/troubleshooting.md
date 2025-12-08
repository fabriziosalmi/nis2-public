# Troubleshooting

Common issues and solutions.

## Installation Issues

### Docker Build Fails

**Problem**: Hash sum mismatch errors during build

```
E: Failed to fetch ... Hash Sum mismatch
```

**Solution**: This is a temporary issue with Debian repositories. Use the existing image or wait for repository sync:

```bash
# Use existing image
docker-compose up -d

# Or retry build later
docker-compose build --no-cache
```

### Permission Denied

**Problem**: Cannot access Docker socket

**Solution**: Add user to docker group:

```bash
sudo usermod -aG docker $USER
newgrp docker
```

## Configuration Issues

### Config File Not Loading

**Problem**: Scanner uses wrong configuration

**Solution**: Verify CONFIG_FILE is set correctly:

```bash
# Check environment variable
echo $CONFIG_FILE

# Verify in container
docker-compose exec scanner cat /app/config.yaml

# Restart with explicit config
CONFIG_FILE=./test_config.yaml docker-compose up -d --force-recreate
```

### Invalid YAML Syntax

**Problem**: Configuration file has syntax errors

**Solution**: Validate YAML:

```bash
# Python validation
python -c "import yaml; yaml.safe_load(open('config.yaml'))"

# Common issues:
# - Use spaces, not tabs for indentation
# - Quote special characters
# - Check list syntax (- item)
```

## Scanning Issues

### Scan Hangs or Times Out

**Problem**: Scan doesn't complete

**Solution**: Increase timeout in config:

```yaml
scan_timeout: 30  # Increase from default 10
concurrency: 5    # Reduce if too many targets
```

### No Targets Found

**Problem**: "Identified 0 targets to scan"

**Solution**: Check target configuration:

```yaml
targets:
  domains:
    - "example.com"  # Ensure domains are listed
  ip_ranges:
    - "192.168.1.0/24"  # Check CIDR notation
```

## Report Issues

### Reports Not Visible

**Problem**: Cannot access reports at localhost:8000

**Solution**: Check scanner service:

```bash
# View logs
docker-compose logs scanner

# Verify service is running
docker-compose ps

# Check port mapping
docker-compose port scanner 8000
```

### Empty or Incomplete Reports

**Problem**: Reports generated but missing data

**Solution**: Check scan completion:

```bash
# View full scan output
docker-compose logs scanner

# Verify evidence collection
docker-compose exec scanner ls -la /app/reports/
```

## Metrics Issues

### Prometheus Not Scraping

**Problem**: Metrics not appearing in Prometheus

**Solution**: Verify metrics file and scrape config:

```bash
# Check metrics file exists
docker-compose exec scanner ls -la /app/reports/nis2_metrics.prom

# Check Node Exporter can read it
docker-compose exec node-exporter cat /var/lib/node_exporter/textfile_collector/nis2_metrics.prom

# Restart Prometheus
docker-compose restart prometheus
```

### Grafana Dashboard Empty

**Problem**: Grafana shows no data

**Solution**: Verify Prometheus datasource:

1. Open Grafana: http://localhost:3000
2. Go to Configuration → Data Sources
3. Check Prometheus URL: `http://prometheus:9090`
4. Test connection
5. Verify metrics exist in Prometheus first

## Network Issues

### Cannot Reach Targets

**Problem**: Scanner cannot connect to targets

**Solution**: Check network connectivity:

```bash
# Test from container
docker-compose exec scanner ping example.com

# Check DNS resolution
docker-compose exec scanner nslookup example.com

# Verify firewall rules
```

### DNS Resolution Fails

**Problem**: Domain names not resolving

**Solution**: Configure DNS in docker-compose:

```yaml
services:
  scanner:
    dns:
      - 8.8.8.8
      - 8.8.4.4
```

## Performance Issues

### Slow Scans

**Problem**: Scans take too long

**Solution**: Optimize configuration:

```yaml
concurrency: 20  # Increase parallel scans
scan_timeout: 5  # Reduce timeout for faster failures
```

### High Memory Usage

**Problem**: Container uses too much memory

**Solution**: Limit resources:

```yaml
services:
  scanner:
    mem_limit: 1g
    cpus: 1.0
```

## Docker Compose Issues

### Version Warning

**Problem**: "attribute `version` is obsolete"

**Solution**: Remove version field from docker-compose.yml:

```yaml
# Remove this line:
# version: '3.8'

services:
  scanner:
    # ...
```

### Service Won't Start

**Problem**: Container exits immediately

**Solution**: Check logs and recreate:

```bash
# View logs
docker-compose logs scanner

# Force recreate
docker-compose up -d --force-recreate

# Rebuild if needed
docker-compose build --no-cache scanner
```

## Getting More Help

If you're still experiencing issues:

1. Check the [GitHub Issues](https://github.com/yourusername/nis2-public/issues)
2. Review [Configuration Guide](/guide/configuration)
3. See [Examples](/examples/) for working setups
4. Open a new issue with:
   - Error messages
   - Configuration file
   - Docker logs
   - Steps to reproduce
