# Strategic Checks Reference

The NIS2 Checker includes "Strategic Checks" designed to go beyond basic technical scanning and address specific NIS2 articles regarding Business Continuity, Supply Chain Security, and Data Protection.

## 1. Domain Continuity (WHOIS)
**NIS2 Article**: Art. 21.2.c (Business Continuity)

This check queries the WHOIS database to find the *administrative* expiration date of the domain. This is critical because a domain can technically resolve (DNS OK) but be days away from administrative deletion.

- **Pass**: > 60 days to expiry.
- **Warn**: < 60 days to expiry.
- **Fail**: < 30 days to expiry (Critical).

## 2. Secrets Detection (Passive)
**NIS2 Article**: Art. 21.2.h (Cryptography / Data Security)

Scans the HTTP response body of the target for patterns resembling leaked secrets. While passive (it does not crawl the whole site), it catches common developer mistakes on landing pages or SPAs.

**Detects**:
- AWS Access Keys (`AKIA...`)
- Google API Keys
- Private Keys (`-----BEGIN PRIVATE KEY-----`)
- Generic 32-char API tokens

## 3. Tech Stack Fingerprinting
**NIS2 Article**: Art. 21.2.d (Supply Chain Security)

Analyzes HTTP headers (`Server`, `X-Powered-By`) and page content to identify the underlying technology stack and flag obsolete or vulnerable components.

**Checks**:
- **Nginx**: Alerts on versions known to be EOL (e.g., < 1.18).
- **PHP**: Alerts on EOL versions (5.x, 7.0, 7.1).
- **jQuery**: Checks for known vulnerable versions mentioned in script tags.

## 4. Visual Evidence (Screenshots)
**NIS2 Article**: Audit Trail compliance

Uses a headless browser (Playwright) to visit the target URL and capture a screenshot. This provides visual proof that the scan was performed and captures the state of the website at the time of audit ("Defacement Detection" baseline).

- **Output**: Screenshots are saved in the `screenshots/` directory with the format `Target_Name.png`.
- **Report**: The path to the screenshot is noted in the JSON/console report.

## 5. DNS Security (Holistic)
**NIS2 Article**: Art. 21.2.f (Cyber Hygiene)

Ensures the domain configuration trusts but verifies.

- **SPF**: Checks for `v=spf1` TXT record to prevent spoofing.
- **DMARC**: Checks for `v=DMARC1` policy.
- **DNSSEC**: Checks for `DNSKEY` presence, ensuring DNS integrity.
