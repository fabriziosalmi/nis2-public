# Quick Start

Get the NIS2 Scanner running in under 5 minutes!

## 1. Start the Scanner

```bash
# Quick mode (no Grafana)
docker-compose up -d
```

This starts:
- **Scanner** (port 8000) - Report server
- **Prometheus** (port 9090) - Metrics collection
- **Node Exporter** - System metrics

## 2. Run a Scan

```bash
# Using the default test configuration
docker-compose exec scanner python -m nis2scan.cli scan
```

## 3. View Results

Open your browser to:
- **Reports**: [http://localhost:8000](http://localhost:8000)
- **Prometheus**: [http://localhost:9090](http://localhost:9090)

## Using a Custom Configuration

```bash
# Create your config file
cat > my_scan.yaml <<EOF
project_name: "Quick Scan"
targets:
  domains:
    - "example.com"
features:
  dns_checks: true
  whois_checks: true
compliance_profile: "standard_nis2"
EOF

# Run with your config
CONFIG_FILE=./my_scan.yaml docker-compose up -d
docker-compose exec scanner python -m nis2scan.cli scan
```

## With Grafana Dashboards

Want visualization? Add Grafana:

```bash
docker-compose -f docker-compose.yml -f docker-compose.grafana.yml up -d
```

Access Grafana at [http://localhost:3000](http://localhost:3000)
- Username: `admin`
- Password: `admin`

## Clean Up

```bash
# Stop all services
docker-compose down

# Remove volumes (deletes Grafana data)
docker-compose down -v
```

## What's Next?

- Learn about [Configuration Options](/guide/configuration)
- Explore [Deployment Strategies](/guide/deployment)
- See [Real Examples](/examples/)
