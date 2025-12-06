# NIS2 Compliance Scan Report

**Date:** 2025-12-06 11:52:47
**Total Targets:** 2

## Summary
| Target | Score | Status | Critical Issues |
|---|---|---|---|
| Example Corp | 0.0% | ❌ FAIL | 0 |
| Google (Test) | 0.0% | ❌ FAIL | 0 |

## Detailed Results
### Example Corp (https://example.com)
**Compliance Score:** 0.0%

#### ❌ Failures
- **Vulnerability Disclosure (RFC 9116)** (Severity.MEDIUM): security.txt not found (404/other)
  - *Remediation: Publish /.well-known/security.txt with 'Contact' and 'Expires' fields.*
- **Privacy Policy** (Severity.HIGH): Privacy Policy link not found
  - *Remediation: Add a visible link to the Privacy Policy.*
- **Security Headers** (Severity.MEDIUM): Missing headers: Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options
  - *Remediation: Configure missing headers (HSTS, CSP, X-Frame-Options).*
- **DNS Integrity (DNSSEC)** (Severity.MEDIUM): Error checking DNSSEC: All nameservers failed to answer the query example.com. IN DNSKEY: Server Do53:192.168.100.1@53 answered REFUSED; Server Do53:1.1.1.1@53 answered REFUSED; Server Do53:8.8.8.8@53 answered REFUSED
  - *Remediation: Enable DNSSEC at your registrar/DNS provider.*

#### ⚠️ Warnings
- **Corporate Identity (P.IVA)**: P.IVA not found on homepage (Mandatory for IT companies)
- **Cookie Compliance**: No common CMP detected (Iubenda, Cookiebot, OneTrust)
- **Resilience (WAF/CDN)**: No WAF/CDN headers detected (Direct exposure?)

---
### Google (Test) (https://google.com)
**Compliance Score:** 0.0%

#### ❌ Failures
- **Privacy Policy** (Severity.HIGH): Privacy Policy link not found
  - *Remediation: Add a visible link to the Privacy Policy.*
- **Security Headers** (Severity.MEDIUM): Missing headers: Strict-Transport-Security, X-Content-Type-Options
  - *Remediation: Configure missing headers (HSTS, CSP, X-Frame-Options).*
- **DNS Integrity (DNSSEC)** (Severity.MEDIUM): Error checking DNSSEC: All nameservers failed to answer the query google.com. IN DNSKEY: Server Do53:192.168.100.1@53 answered REFUSED; Server Do53:1.1.1.1@53 answered REFUSED; Server Do53:8.8.8.8@53 answered REFUSED
  - *Remediation: Enable DNSSEC at your registrar/DNS provider.*

#### ⚠️ Warnings
- **Corporate Identity (P.IVA)**: P.IVA not found on homepage (Mandatory for IT companies)
- **Cookie Compliance**: No common CMP detected (Iubenda, Cookiebot, OneTrust)
- **Resilience (WAF/CDN)**: No WAF/CDN headers detected (Direct exposure?)

---
