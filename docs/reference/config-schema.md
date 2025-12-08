# Configuration Schema Reference

Complete reference for all configuration options.

## Root Level

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `project_name` | string | Yes | - | Name of your scan project |
| `scan_timeout` | integer | No | 10 | Timeout in seconds for each operation |
| `concurrency` | integer | No | 10 | Number of concurrent scan threads |
| `targets` | object | Yes | - | Target specification |
| `features` | object | No | {} | Feature toggles |
| `compliance_profile` | string | No | "standard_nis2" | Compliance profile to use |

## Targets

### targets.domains

List of domain names to scan.

**Type**: `array<string>`  
**Required**: No  
**Default**: `[]`

**Example**:
```yaml
targets:
  domains:
    - "example.com"
    - "www.example.com"
```

### targets.ip_ranges

List of IP addresses or CIDR ranges.

**Type**: `array<string>`  
**Required**: No  
**Default**: `[]`

**Example**:
```yaml
targets:
  ip_ranges:
    - "192.168.1.0/24"
    - "10.0.0.1"
```

### targets.asns

List of ASN numbers (experimental).

**Type**: `array<integer>`  
**Required**: No  
**Default**: `[]`

**Example**:
```yaml
targets:
  asns:
    - 15169  # Google
```

## Features

### features.dns_checks

Enable DNS security checks (DNSSEC, AXFR).

**Type**: `boolean`  
**Required**: No  
**Default**: `true`

**Example**:
```yaml
features:
  dns_checks: true
```

### features.whois_checks

Enable WHOIS domain expiry monitoring.

**Type**: `boolean`  
**Required**: No  
**Default**: `true`

**Example**:
```yaml
features:
  whois_checks: true
```

## Compliance Profiles

### standard_nis2

Standard NIS2 Directive compliance checks.

**Includes**:
- Port exposure detection
- TLS/SSL configuration
- HTTP security headers
- DNS security
- Basic threat detection

### strict

Stricter compliance requirements.

**Includes**:
- All standard_nis2 checks
- Enhanced secret detection
- Stricter TLS requirements
- Additional security headers

### custom

Custom compliance rules (requires configuration).

## Complete Example

```yaml
# Full configuration example
project_name: "Production Infrastructure Audit"
scan_timeout: 30
concurrency: 20

targets:
  domains:
    - "example.com"
    - "www.example.com"
    - "api.example.com"
  ip_ranges:
    - "203.0.113.0/24"
  asns: []

features:
  dns_checks: true
  whois_checks: true

compliance_profile: "strict"
```

## Validation

Validate your configuration:

```bash
# Python validation
python -c "import yaml; yaml.safe_load(open('config.yaml'))"

# Docker validation
docker-compose config
```

## Environment Variables

Configuration can also use environment variables:

```yaml
project_name: "${PROJECT_NAME:-Default Project}"
scan_timeout: ${SCAN_TIMEOUT:-10}
```

## Next Steps

- [Configuration Guide](/guide/configuration) - How to use configs
- [Examples](/examples/) - Real-world configurations
- [CLI Reference](/reference/cli) - Command-line options
