# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.2.x   | Yes       |
| < 2.2   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do NOT open a public issue.**
2. Email: [fabrizio.salmi@gmail.com](mailto:fabrizio.salmi@gmail.com) (or use GitHub's private vulnerability reporting)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We aim to acknowledge reports within 48 hours and provide a fix within 7 days for critical issues.

## Security Measures

This platform implements the following security controls:

### Authentication and Authorization
- JWT-based authentication with configurable secret rotation
- Role-based access control (admin, auditor, viewer)
- Rate limiting on auth endpoints (10 requests/minute via slowapi)
- API key authentication for CI/CD integrations

### Network Security
- CORS restricted to explicit allow-list (no wildcards)
- SSRF prevention on all user-supplied URLs and IPs
- CSP, HSTS, X-Frame-Options, and Permissions-Policy headers
- Input validation on all scan targets

### Data Protection
- Multi-tenant isolation at the database level
- No secrets stored in version control
- `.env.example` contains only placeholder instructions, not real values

### Operational Security
- Audit logging for all state-changing operations
- GitHub Actions CI with automated security gates
- Dependency scanning via GitHub Dependabot

## Secrets Management

See `docs/guide/secrets-rotation.md` for the rotation procedure covering:
- `JWT_SECRET`
- `NEXTAUTH_SECRET`
- Database credentials
- API keys
