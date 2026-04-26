# Secrets Rotation Guide

> **NIS2 Compliance Platform — Secrets Management & Rotation**

## Required Secrets

| Secret | File | Purpose | Rotation Frequency |
|--------|------|---------|-------------------|
| `JWT_SECRET` | `.env` | Signs access/refresh tokens | Every 90 days |
| `NEXTAUTH_SECRET` | `.env` | Signs Next.js session cookies | Every 90 days |
| `POSTGRES_PASSWORD` | `.env` | PostgreSQL authentication | Every 180 days |
| `REDIS_URL` | `.env` | Redis connection (if auth enabled) | As needed |

## Generating Strong Secrets

```bash
# Generate a 256-bit random secret (recommended)
openssl rand -base64 32

# Alternative: Python
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# Alternative: Node.js
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
```

## Rotation Procedure

### JWT_SECRET Rotation

**Impact**: All existing access and refresh tokens become invalid. Users must re-login.

```bash
# 1. Generate new secret
NEW_SECRET=$(openssl rand -base64 32)

# 2. Update .env
sed -i "s/^JWT_SECRET=.*/JWT_SECRET=$NEW_SECRET/" .env

# 3. Restart API service
docker compose -f infra/docker/docker-compose.prod.yml restart api worker

# 4. Verify
curl -s http://localhost:8000/api/v1/health | jq .
```

**Grace period**: There is no dual-key support. Rotation is immediate — all sessions are invalidated.

### NEXTAUTH_SECRET Rotation

**Impact**: All frontend sessions are invalidated. Users must re-login.

```bash
NEW_SECRET=$(openssl rand -base64 32)
sed -i "s/^NEXTAUTH_SECRET=.*/NEXTAUTH_SECRET=$NEW_SECRET/" .env
docker compose -f infra/docker/docker-compose.prod.yml restart web
```

### POSTGRES_PASSWORD Rotation

**Impact**: Requires coordinated update of both PostgreSQL and the API service.

```bash
# 1. Connect to PostgreSQL and change password
docker compose -f infra/docker/docker-compose.prod.yml exec db \
  psql -U nis2 -c "ALTER USER nis2 PASSWORD 'new_password_here';"

# 2. Update .env
sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=new_password_here/" .env

# 3. Restart API + worker
docker compose -f infra/docker/docker-compose.prod.yml restart api worker
```

## Security Checklist

- [ ] `.env` is in `.gitignore` and **never committed to git**
- [ ] Secrets are at least 32 characters of random data
- [ ] Different secrets are used in development vs. production
- [ ] Secrets are rotated after any team member departure
- [ ] Secrets are rotated after any suspected compromise
- [ ] Production secrets are stored in a secrets manager (Vault, AWS SSM, etc.) when possible
- [ ] `JWT_SECRET` and `NEXTAUTH_SECRET` are different values

## Production Recommendations

1. **Use a secrets manager** (HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager)
2. **Set up rotation reminders** in your calendar (90-day cycle)
3. **Audit `.env` access** — restrict read permissions to the Docker user only:
   ```bash
   chmod 600 .env
   chown root:root .env
   ```
4. **Never log secrets** — ensure your logging configuration excludes environment variables
5. **Use Docker secrets** in Swarm mode or Kubernetes secrets in K8s deployments
