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

**NIS2 mapping**: Art. 21(e) — secure acquisition, 21(h) — cryptography and network security.

## TLS/SSL

- **Protocol version detection**: connects to port 443/8443 and reads the negotiated TLS version.
- **Weak version probing**: attempts connections forcing TLS 1.0 and TLS 1.1 individually. Flags them if the server accepts these deprecated versions.
- **Cipher detection**: reports the cipher suite negotiated on the primary connection.
- **Certificate validation**: uses Python's `ssl` module to retrieve the peer certificate. Checks chain trust and hostname match.

**NIS2 mapping**: Art. 21(h) — cryptography.

## HTTP Security Headers

The scanner performs an HTTP GET to the root path of each domain and inspects the response headers.

### Required headers

| Header | Purpose | Finding when absent |
|---|---|---|
| `Strict-Transport-Security` | Enforce HTTPS, prevent protocol downgrade (HSTS) | Medium |
| `Content-Security-Policy` | Restrict resource origins, mitigate XSS and injection | Medium |
| `X-Frame-Options` | Prevent clickjacking via iframe embedding | Medium |

### Information-leaking headers

The scanner captures these headers when present and includes them in the finding detail. Presence is informational — they disclose technology stack details that aid attackers.

| Header | What it leaks |
|---|---|
| `Server` | Web server name and version |
| `X-Powered-By` | Runtime or framework |
| `X-AspNet-Version` | ASP.NET version |
| `X-Generator` | CMS or generator |

**NIS2 mapping**: Art. 21(e) — secure acquisition and development.

## DNS Security

DNS checks use `dnspython` and run in a thread executor to avoid blocking the async loop.

- **DNSSEC**: queries for `DNSKEY` records on the domain. If present, DNSSEC is reported as enabled.
- **Zone transfer (AXFR)**: resolves the domain's NS records, then attempts an AXFR transfer against each nameserver. Flags the domain if any nameserver allows it.
- **SPF**: queries TXT records for the domain and looks for a record starting with `v=spf1`.
- **DMARC**: queries TXT records at `_dmarc.<domain>` and looks for a record starting with `v=DMARC1`.

DNS checks are only run when the target is a domain (not an IP address or CIDR range).

**NIS2 mapping**: Art. 21(e) — secure network configuration.

## Legal Compliance

Legal checks use `playwright` (headless browser) to render the page and analyze the DOM. They only run on root domains and `www.` subdomains, not on IP addresses or service subdomains.

- **P.IVA (VAT number)**: searches for an Italian VAT number pattern (11 digits) in the page content. Required by Italian law for commercial sites.
- **Privacy policy**: searches for keywords like "privacy policy", "informativa privacy" in the rendered page.
- **Cookie banner**: searches for cookie consent keywords ("cookie", "accetta", "accept cookies", "manage cookies", etc.) in the rendered page.

**NIS2 mapping**: Art. 21(a) — risk policies and governance.

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

**NIS2 mapping**: Art. 21(e) — secure development practices.

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

## Compliance Engine

After the checks finish, the compliance engine turns findings into a score.

It is computed **per host, then averaged over the hosts that answered** — not
per NIS2 article. Each host starts at 100 and every finding on it deducts:

| Severity | Deduction |
|---|---|
| CRITICAL | −50 |
| HIGH | −20 |
| MEDIUM | −10 |
| LOW | −5 |
| INFO | none — informational findings never move the score |

A host score is floored at 0, and the scan's score is the mean of the host
scores over `active_hosts` (the hosts that responded).

**A scan that assessed nothing has no score at all.** Both ways that happens —
no target resolved, or targets that never answered — used to produce 100/100,
which reads as a clean bill of health for a scan that observed nothing. The
score is now `null`, carrying the reason instead.

Alongside the score the engine stores a `compliance_matrix` snapshot on the
scan, mapping findings to the Art. 21(2) sub-paragraphs.

Read the number conservatively: 70 means there are material open findings, not
that the organisation is 70% compliant with the directive.
