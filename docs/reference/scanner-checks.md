# Scanner Checks

The scanner runs automated checks against each target. Checks are grouped by category and mapped to NIS2 Art. 21 articles.

## Port Scanning

Scans for open ports on the following services:

| Port | Service |
|---|---|
| 21 | FTP |
| 22 | SSH |
| 23 | Telnet |
| 53 | DNS |
| 80 | HTTP |
| 443 | HTTPS |
| 445 | SMB |
| 3306 | MySQL |
| 3389 | RDP |
| 5432 | PostgreSQL |
| 6379 | Redis |
| 8080 | HTTP Alternate |
| 8443 | HTTPS Alternate |
| 27017 | MongoDB |

Each port is probed with an async TCP connection (2-second timeout). Findings are generated for exposed management ports (SSH, RDP, Telnet, SMB) and cleartext protocols (FTP, HTTP, Telnet), as well as exposed database ports (MySQL, PostgreSQL, Redis, MongoDB).

## TLS/SSL

- **Protocol version detection**: connects to port 443/8443 and reads the negotiated TLS version.
- **Weak version probing**: attempts connections forcing TLS 1.0 and TLS 1.1 individually. Flags them if the server accepts these deprecated versions.
- **Cipher detection**: reports the cipher suite negotiated on the primary connection.
- **Certificate validation**: uses Python's `ssl` module to retrieve the peer certificate. Checks chain trust and hostname match.

## HTTP Security Headers

Checks for the presence of these headers on HTTP/HTTPS responses:

| Header | Purpose |
|---|---|
| `Strict-Transport-Security` | Enforce HTTPS (HSTS) |
| `Content-Security-Policy` | XSS and injection mitigation |
| `X-Frame-Options` | Clickjacking protection |

The scanner records all response headers. Information-leaking headers are also captured: `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator`.

## DNS Security

DNS checks use `dnspython` and run in a thread executor to avoid blocking the async loop.

- **DNSSEC**: queries for `DNSKEY` records on the domain. If present, DNSSEC is reported as enabled.
- **Zone transfer (AXFR)**: resolves the domain's NS records, then attempts an AXFR transfer against each nameserver. Flags the domain if any nameserver allows it.
- **SPF**: queries TXT records for the domain and looks for a record starting with `v=spf1`.
- **DMARC**: queries TXT records at `_dmarc.<domain>` and looks for a record starting with `v=DMARC1`.

DNS checks are only run when the target is a domain (not an IP address or CIDR range).

## Legal Compliance

Legal checks use `playwright` (headless browser) to render the page and analyze the DOM. They only run on root domains and `www.` subdomains, not on IP addresses or service subdomains.

- **P.IVA (VAT number)**: searches for an Italian VAT number pattern (11 digits) in the page content. Required by Italian law for commercial sites.
- **Privacy policy**: searches for keywords like "privacy policy", "informativa privacy" in the rendered page.
- **Cookie banner**: searches for cookie consent keywords ("cookie", "accetta", "accept cookies", "manage cookies", etc.) in the rendered page.

## Secrets Detection

Scans the HTML body of HTTP responses for leaked secrets. The scanner checks for these patterns (defined in `secrets.py`):

| Pattern | Description |
|---|---|
| `AKIA[0-9A-Z]{16}` | AWS access keys |
| `aws_secret_access_key = ...` | AWS secret keys |
| `-----BEGIN (RSA\|EC\|DSA) PRIVATE KEY-----` | Private keys (RSA, EC, DSA) |
| `ghp_[a-zA-Z0-9]{36}` | GitHub personal access tokens |
| `api[_-]?key[:=] ...` | Generic API key assignments (20+ character values) |
| `eyJ...` (three Base64 segments separated by dots) | JWT tokens in page source |

## WHOIS

- **Domain expiry**: uses `python-whois` to look up the domain's expiration date. Flags domains expiring within 30 days.

WHOIS checks are only run when the target is a domain.

## WAF/CDN Detection

Detects the presence of Web Application Firewalls and CDN providers by matching response headers and cookie values against known indicators:

- Cloudflare (cf-ray header, __cfduid cookie)
- Akamai (x-akamai header)
- AWS CloudFront (x-amz-cf-id header)
- Fastly (x-fastly header)
- Incapsula/Imperva (incap_ses, visid_incap cookies)
- Sucuri (x-sucuri-id header)

## Sensitive Files

Probes for files that should not be publicly accessible:

| Path | Detection Logic |
|---|---|
| `/.git/HEAD` | Returns 200 and body contains `ref: refs/` |
| `/.env` | Returns 200 and body contains `=` |

Responses are validated to avoid false positives from custom 404 pages that return HTTP 200.

## security.txt

Checks for the presence of `/.well-known/security.txt` per RFC 9116. Falls back to `/security.txt` if the well-known path returns a non-200 status.

## Subresource Integrity

Parses the HTML body for external `<script>` tags (those with an `src` attribute pointing to a different host). Flags scripts that do not include an `integrity` attribute (SRI).

## Cookie Security

Analyzes `Set-Cookie` headers in the HTTP response:

- **Secure** flag: cookie should only be sent over HTTPS.
- **HttpOnly** flag: cookie should not be accessible via JavaScript.
- **SameSite** attribute: CSRF protection.
