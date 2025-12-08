# Features

## Security Scanning

### Port Exposure Detection

Automatically detects exposed critical services:
- Database ports (MySQL, PostgreSQL, MongoDB, Redis)
- File sharing (SMB, NFS)
- Remote access (RDP, Telnet, SSH)
- FTP and legacy protocols

### TLS/SSL Configuration

Checks for:
- Certificate validity and expiration
- Supported TLS versions
- Weak cipher suites
- Certificate chain issues

### HTTP Security Headers

Validates presence and configuration of:
- HSTS (HTTP Strict Transport Security)
- CSP (Content Security Policy)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy

## DNS Security

### DNSSEC Validation

- Checks for DNSSEC implementation
- Validates DNSSEC signatures
- Reports configuration issues

### Zone Transfer Detection

- Tests for unauthorized AXFR
- Identifies DNS misconfigurations
- Detects information leakage

## Compliance Checks

### NIS2 Directive Requirements

Automated checks for:
- Network security measures
- Incident handling capabilities
- Business continuity
- Supply chain security
- Security in network and information systems acquisition

### Italian Legal Compliance

Specific checks for Italian requirements:
- P.IVA (VAT number) presence
- Privacy policy availability
- Cookie consent banners
- GDPR compliance indicators

## Threat Detection

### Secrets Detection

Scans for exposed:
- AWS access keys
- API tokens
- Private keys
- Database credentials
- OAuth tokens

### WAF/CDN Detection

Identifies protective services:
- Cloudflare
- AWS CloudFront
- Akamai
- Other CDN providers

## Monitoring & Reporting

### Multiple Report Formats

- **HTML**: Interactive web reports with charts
- **JSON**: Machine-readable for automation
- **Markdown**: Human-readable text format
- **Evidence Bundle**: ZIP with all collected data

### Prometheus Integration

Export metrics for:
- Compliance scores
- Finding counts by severity
- Scan statistics
- Historical tracking

### Grafana Dashboards

Pre-built dashboards showing:
- Compliance score gauges
- Findings by severity over time
- Target status overview
- Scan history

## Domain Management

### WHOIS Monitoring

Track:
- Domain expiration dates
- Registrar information
- Administrative contacts
- Registration changes

### Certificate Monitoring

Monitor:
- SSL/TLS certificate expiration
- Certificate authority
- Subject alternative names
- Certificate revocation status

## Evidence Collection

### Automated Evidence Gathering

Collects:
- HTTP responses
- DNS records
- Certificate chains
- Port scan results
- Security header configurations

### Audit-Ready Reports

Generates:
- Timestamped evidence bundles
- Detailed finding descriptions
- Remediation recommendations
- Compliance mapping

## Customization

### Configurable Scans

Customize:
- Target selection (domains, IPs, ASNs)
- Scan timeout and concurrency
- Feature toggles
- Compliance profiles

### Extensible Architecture

Easy to extend with:
- Custom compliance rules
- Additional security checks
- New report formats
- Integration plugins

## Performance

### Concurrent Scanning

- Parallel target scanning
- Configurable thread pools
- Optimized for large-scale scans

### Resource Efficiency

- Minimal memory footprint
- Docker-optimized
- Scalable architecture

## Next Steps

- [Getting Started](/guide/getting-started) - Install and run
- [Configuration](/guide/configuration) - Customize features
- [Examples](/examples/) - See features in action
