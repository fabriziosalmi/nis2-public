# Secrets Rotation Guide

> **NIS2 Compliance Platform — Secrets Management & Rotation**

## Required Secrets

| Secret | File | Purpose | Rotation Frequency |
|--------|------|---------|-------------------|
| `JWT_SECRET` | `.env` | Signs access/refresh tokens | Every 90 days |
| `DATA_ENCRYPTION_KEY` | `.env` | Encrypts MFA seeds, notification credentials and leaked-secret evidence at rest | Every 180 days — **read the procedure below first** |
| `POSTGRES_PASSWORD` | `.env` | PostgreSQL authentication | Every 180 days |
| `NIS2_APP_PASSWORD` | `.env` | The NOSUPERUSER runtime database role that makes RLS bind | Every 180 days |
| `REDIS_PASSWORD` | `.env` | Redis authentication (broker + rate-limit counters) | As needed |

`NEXTAUTH_SECRET` was removed in 2.6.x — `next-auth` is not a dependency of
`packages/web` and nothing reads the variable. If your `.env` still carries one,
it is inert and can be deleted.

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

### DATA_ENCRYPTION_KEY Rotation

**This is the one rotation that can lose data if performed naively.**

`DATA_ENCRYPTION_KEY` encrypts, at rest, every TOTP/MFA seed, every notification
channel credential, and the leaked-secret evidence attached to findings.
Replacing it without re-encrypting leaves all of those unreadable — and until
2.6.16 the failure was silent: the decrypt path returned the ciphertext instead
of raising, so the only symptom was every MFA-enrolled user finding that their
codes no longer matched.

Rotate through an overlap, not a cliff:

```bash
# 1. Old key becomes the fallback; new key becomes current.
OLD_KEY=$(grep '^DATA_ENCRYPTION_KEY=' .env | cut -d= -f2-)
NEW_KEY=$(openssl rand -base64 32)
sed -i "s|^DATA_ENCRYPTION_KEY=.*|DATA_ENCRYPTION_KEY=$NEW_KEY|" .env
echo "DATA_ENCRYPTION_KEY_PREVIOUS=$OLD_KEY" >> .env

# 2. Restart so both keys are accepted for reading. New writes use the new key.
docker compose -f infra/docker/docker-compose.prod.yml up -d api celery-worker

# 3. Check what would move, then move it.
make reencrypt-dry-run
make reencrypt

# 4. Remove the fallback and restart. Anything missed now fails loudly.
sed -i '/^DATA_ENCRYPTION_KEY_PREVIOUS=/d' .env
docker compose -f infra/docker/docker-compose.prod.yml up -d api celery-worker
```

**Impact**: none, if the sequence is followed — no user is logged out and no MFA
enrolment is lost. Skipping step 3 loses every MFA enrolment and every stored
channel credential.

**Grace period**: as long as `DATA_ENCRYPTION_KEY_PREVIOUS` remains set. Leaving
it set indefinitely is not harmful to availability, but it keeps the old key on
disk, so remove it once step 3 reports zero unreadable values.

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
- [ ] `JWT_SECRET` and `DATA_ENCRYPTION_KEY` are different values
- [ ] `DATA_ENCRYPTION_KEY` is backed up somewhere the database backup is not — losing it makes every encrypted column unreadable, and no restore brings it back

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
