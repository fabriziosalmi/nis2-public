# Configuration Guide

## Configuration File Formats

The NIS2 Scanner supports flexible configuration through YAML files. You can specify different configuration files depending on your environment or use case.

## Specifying Configuration Files

### Method 1: CONFIG_FILE Environment Variable (Recommended)

Use the `CONFIG_FILE` environment variable to specify which configuration file to use:

```bash
# Use test_config.yaml
CONFIG_FILE=./test_config.yaml docker-compose up -d

# Use config_prod.yaml
CONFIG_FILE=./config_prod.yaml docker-compose up -d

# Default: uses config.yaml
docker-compose up -d
```

### Method 2: .env File

Create a `.env` file in the project root:

```bash
# .env
CONFIG_FILE=./test_config.yaml
```

Then run normally:
```bash
docker-compose up -d
```

### Method 3: Docker Compose Override

Create `docker-compose.override.yml`:

```yaml
version: '3.8'
services:
  scanner:
    volumes:
      - ./test_config.yaml:/app/config.yaml:ro
```

Docker Compose will automatically load it:
```bash
docker-compose up -d
```

### Method 4: Scan Command Flag

Specify configuration at scan time:

```bash
docker-compose up -d
docker-compose exec scanner python -m nis2scan.cli scan -c /app/configs/custom.yaml
```

## Configuration Schema

### Basic Structure

```yaml
project_name: "My Scan Project"
scan_timeout: 10
concurrency: 10

targets:
  ip_ranges: []
  domains:
    - "example.com"
  asns: []

features:
  dns_checks: true
  whois_checks: true

compliance_profile: "standard_nis2"
```

### Configuration Options

#### Project Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `project_name` | string | Required | Name of your scan project |
| `scan_timeout` | integer | 10 | Timeout in seconds for each scan operation |
| `concurrency` | integer | 10 | Number of concurrent scan threads |

#### Targets

| Field | Type | Description |
|-------|------|-------------|
| `ip_ranges` | list | List of IP addresses or CIDR ranges to scan |
| `domains` | list | List of domain names to scan |
| `asns` | list | List of ASN numbers to scan (experimental) |

#### Features

| Feature | Type | Default | Description |
|---------|------|---------|-------------|
| `dns_checks` | boolean | true | Enable DNS security checks (DNSSEC, AXFR) |
| `whois_checks` | boolean | true | Enable WHOIS domain expiry monitoring |

#### Compliance Profile

| Profile | Description |
|---------|-------------|
| `standard_nis2` | Standard NIS2 compliance checks |
| `strict` | Stricter compliance requirements |
| `custom` | Custom compliance rules |

## Example Configurations

### Test/Development

```yaml
project_name: "Development Scan"
scan_timeout: 5
concurrency: 10

targets:
  domains:
    - "example.com"

features:
  dns_checks: true
  whois_checks: true

compliance_profile: "standard_nis2"
```

### Production

```yaml
project_name: "Production Infrastructure Scan"
scan_timeout: 30
concurrency: 20

targets:
  domains:
    - "mycompany.com"
    - "api.mycompany.com"
    - "app.mycompany.com"
  ip_ranges:
    - "192.168.1.0/24"

features:
  dns_checks: true
  whois_checks: true

compliance_profile: "strict"
```

### Multi-Target Scan

```yaml
project_name: "Multi-Environment Scan"
scan_timeout: 15
concurrency: 15

targets:
  domains:
    - "staging.example.com"
    - "production.example.com"
    - "api.example.com"

features:
  dns_checks: true
  whois_checks: true

compliance_profile: "standard_nis2"
```

## Best Practices

### Development
- Use `.env` file with `CONFIG_FILE=./test_config.yaml`
- Keep timeout low for faster iterations
- Use limited target list

### CI/CD
- Use `CONFIG_FILE` environment variable
- Store configs in version control
- Use different configs per environment

### Production
- Use `CONFIG_FILE=./config_prod.yaml`
- Increase timeout for thorough scans
- Enable all security features
- Use strict compliance profile

### Testing
- Mount `configs/` directory
- Use scan `-c` flag for multiple configs
- No need to restart container

## Validation

Verify your configuration:

```bash
# Check which config is mounted
docker-compose config | grep -A 2 "config.yaml"

# View config inside container
docker-compose exec scanner cat /app/config.yaml

# Validate YAML syntax
python -c "import yaml; yaml.safe_load(open('my_config.yaml'))"
```

## Troubleshooting

### Config Not Loading

```bash
# Verify environment variable
echo $CONFIG_FILE

# Check docker-compose config
docker-compose config

# Restart with explicit config
CONFIG_FILE=./test_config.yaml docker-compose up -d --force-recreate
```

### Invalid YAML

```bash
# Validate syntax
python -c "import yaml; yaml.safe_load(open('config.yaml'))"

# Common issues:
# - Incorrect indentation (use spaces, not tabs)
# - Missing quotes around special characters
# - Invalid list syntax
```
