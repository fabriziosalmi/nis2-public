# Scanner Checks

The scanner runs 50+ automated checks against each target. Checks are grouped by category and mapped to NIS2 Art. 21 articles.

## Port Scanning

Scans for open ports on common services:

| Port | Service |
|---|---|
| 21 | FTP |
| 22 | SSH |
| 23 | Telnet |
| 25 | SMTP |
| 53 | DNS |
| 80 | HTTP |
| 110 | POP3 |
| 143 | IMAP |
| 443 | HTTPS |
| 445 | SMB |
| 993 | IMAPS |
| 995 | POP3S |
| 3389 | RDP |
| 8080 | HTTP Alternate |

Findings are generated for exposed management ports (SSH, RDP, Telnet, SMB) and cleartext protocols (FTP, HTTP, Telnet).

## TLS/SSL

- **Protocol version detection**: identifies TLS 1.0, 1.1, 1.2, and 1.3 support. Flags TLS 1.0 and 1.1 as deprecated.
- **Weak cipher detection**: checks for known weak cipher suites (RC4, DES, 3DES, export ciphers, NULL ciphers).
- **Certificate validation**: verifies chain trust, expiry date, and hostname match.
- **Certificate expiry warning**: flags certificates expiring within 30 days.
- **Weak key detection**: flags RSA keys under 2048 bits and ECDSA keys under 256 bits.

## HTTP Security Headers

Checks for the presence and correct configuration of:

| Header | Purpose |
|---|---|
| `Strict-Transport-Security` | Enforce HTTPS (HSTS) |
| `X-Content-Type-Options` | Prevent MIME sniffing |
| `X-Frame-Options` | Clickjacking protection |
| `Content-Security-Policy` | XSS and injection mitigation |
| `Referrer-Policy` | Control referrer information leakage |
| `Permissions-Policy` | Restrict browser feature access |
| `X-XSS-Protection` | Legacy XSS filter (deprecated but checked) |
| `Cache-Control` | Sensitive page caching policy |

Also checks for information-leaking headers: `Server`, `X-Powered-By`, `X-AspNet-Version`.

## DNS Security

- **DNSSEC**: verifies DNSSEC signing is active on the domain.
- **Zone transfer (AXFR)**: tests if DNS zone transfer is allowed (should be denied).
- **SPF**: checks for a valid SPF record on the domain.
- **DMARC**: checks for a DMARC policy record.
- **MX records**: validates mail server configuration and checks for open relays.

## Legal Compliance

- **P.IVA (VAT number)**: checks for the presence of an Italian VAT number on the website (required by Italian law for commercial sites).
- **Privacy policy**: detects the presence of a privacy policy page.
- **Cookie banner**: checks for a cookie consent mechanism.

## Secrets Detection

Scans publicly accessible pages and responses for leaked secrets matching common patterns:

- AWS access keys and secret keys
- Google API keys
- GitHub tokens
- Generic API keys and tokens
- Private keys (RSA, SSH)
- Database connection strings
- JWT tokens in page source

## WHOIS

- **Domain expiry**: checks domain registration expiry date and flags domains expiring within 30 days.
- **Registrar lock**: verifies domain has transfer lock enabled.
- **WHOIS data accuracy**: validates registrant contact information is present.

## WAF/CDN Detection

Detects the presence of Web Application Firewalls and CDN providers by analyzing response headers and behavior patterns. Identifies:

- Cloudflare, AWS CloudFront, Akamai, Fastly, Sucuri, Imperva
- Generic WAF signatures

## Sensitive Files

Probes for files and directories that should not be publicly accessible:

- `/.git/` (Git repository exposure)
- `/.env` (environment variables)
- `/wp-admin/`, `/wp-login.php` (WordPress admin)
- `/server-status`, `/server-info` (Apache status pages)
- `/phpinfo.php`
- `/robots.txt` (analyzed for hidden paths)
- `/sitemap.xml`

## security.txt

Validates the presence and format of `/.well-known/security.txt` per RFC 9116:

- File exists and is accessible
- Contains required `Contact` field
- Contains `Expires` field with a future date
- Optionally checks for `Encryption`, `Preferred-Languages`, and `Policy` fields

## Subresource Integrity

Checks that externally loaded scripts and stylesheets include `integrity` attributes (SRI) to prevent supply-chain attacks via CDN compromise.

## Cookie Security

Analyzes cookies set by the application:

- `Secure` flag (cookies only sent over HTTPS)
- `HttpOnly` flag (cookies not accessible via JavaScript)
- `SameSite` attribute (CSRF protection)
