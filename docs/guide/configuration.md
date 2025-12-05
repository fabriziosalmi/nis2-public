# Configuration

## Global Settings (`config.yaml`)
Configure timeouts, enabled checks, and required headers.

```yaml
timeout: 10
checks:
  ssl_tls: true
  security_headers: true
  connectivity: true
  ssh_password: true
  tls_deprecated: true
  http_cleartext: true
  windows_rdp: true
  windows_smb: true

nmap:
  enabled: true
  timing: 3 # 0-5 (0=paranoid, 3=normal, 5=insane)
  discovery: true # Enable ping scan for CIDR targets
  ports:
    ssh: 22
    https: 443
    http_mgmt: [80, 8080]
    rdp: 3389
    smb: 445

ssl:
  min_version: "TLSv1.2"

headers:
  required:
    - "Strict-Transport-Security"
    - "X-Content-Type-Options"
```

## Targets (`targets.yaml`)
Define your targets using URLs, IPs, or CIDR notation.

```yaml
targets:
  - url: "https://example.com"
    name: "Example Web"
    type: "web"
  
  - ip: "192.168.1.10"
    name: "Internal Server"
    type: "ssh"

  - ip: "192.168.1.0/24"
    name: "Office Network"
    type: "generic" # Scans all hosts in subnet
```

### Target Types
- `web` / `https`: Runs SSL, Headers, and Web Port checks.
- `ssh`: Runs SSH Authentication checks.
- `windows`: Runs RDP and SMB security checks.
- `generic`: Runs a broad set of safe checks.
