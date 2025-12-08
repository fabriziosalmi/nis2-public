# NIS2 Compliance Scanner

Automated NIS2 Directive compliance scanning and reporting tool with comprehensive security checks, multiple report formats, and Docker deployment.

## Features

- 🔍 **Comprehensive Scanning**: Ports, TLS/SSL, HTTP headers, DNS security
- 📊 **Multiple Report Formats**: HTML, JSON, Markdown with evidence collection
- 🐳 **Docker Ready**: Easy deployment with optional Grafana dashboards
- 🔐 **Security Focused**: Secrets detection, WAF/CDN identification, domain monitoring
- 🇮🇹 **Italian Compliance**: P.IVA, privacy policy, cookie consent checks
- 📈 **Prometheus Integration**: Metrics export for monitoring

## Quick Start

```bash
# Start the scanner
docker-compose up -d

# Initialize configuration (Interactive)
docker-compose exec scanner python -m nis2scan.cli init

# Run a scan
docker-compose exec scanner python -m nis2scan.cli scan

# View reports (HTTPS enabled by default)
open https://localhost
```

## Documentation

Full documentation is available at: **[https://yourusername.github.io/nis2-public](https://yourusername.github.io/nis2-public)**

- [Getting Started](https://yourusername.github.io/nis2-public/guide/getting-started)
- [Quick Start](https://yourusername.github.io/nis2-public/guide/quick-start)
- [Configuration Guide](https://yourusername.github.io/nis2-public/guide/configuration)
- [Docker Guide](https://yourusername.github.io/nis2-public/guide/docker)
- [Examples](https://yourusername.github.io/nis2-public/examples/)

## Installation

### Docker (Recommended)

```bash
git clone https://github.com/fabriziosalmi/nis2-public.git
cd nis2-public
docker-compose up -d
```

### Local

```bash
git clone https://github.com/fabriziosalmi/nis2-public.git
cd nis2-public
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
playwright install chromium
python -m nis2scan.cli scan
```

## Configuration

Create a `config.yaml`:

```yaml
# config.yaml
project_name: "My Scan"
targets:
  domains: ["example.com"]

features:
  dns_checks: true    # DNSSEC & Zone Transfer detection
  web_checks: true    # HTTP headers, TLS, WAF/CDN, legal compliance
  port_scan: true     # Network port scanning
  whois_checks: true  # Domain expiry monitoring
```
compliance_profile: "standard_nis2"
```

Run with your config:

```bash
CONFIG_FILE=./config.yaml docker-compose up -d
docker-compose exec scanner python -m nis2scan.cli scan
```

## Deployment Options

### Quick Mode (No Grafana)

```bash
docker-compose up -d
```

Services:
- **Traefik** (80/443): Reverse Proxy with automatic HTTPS (self-signed)
- **Scanner**: Backend service (accessible via Traefik)
- **Prometheus** (9090): Metrics
- **Node Exporter**: Host metrics

Access reports at **https://localhost** (accept the self-signed certificate warning).

### Full Stack (With Grafana)

```bash
docker-compose -f docker-compose.yml -f docker-compose.grafana.yml up -d
```

Additional: Grafana (3000)

## Reports

After a scan, find reports in `reports/`:

- **HTML**: Interactive web report
- **JSON**: Machine-readable format
- **Markdown**: Human-readable text
- **Evidence Bundle**: ZIP with all collected data
- **Prometheus Metrics**: For monitoring

## Development

### Build Documentation

```bash
npm run docs:dev   # Development server
npm run docs:build # Production build
```

### Run Tests

```bash
python -m pytest tests/
```

## Contributing

Contributions are welcome! Please read our contributing guidelines.

## License

MIT License - see LICENSE file for details

## Support

- Documentation: https://yourusername.github.io/nis2-public
- Issues: https://github.com/fabriziosalmi/nis2-public/issues
- Discussions: https://github.com/fabriziosalmi/nis2-public/discussions
