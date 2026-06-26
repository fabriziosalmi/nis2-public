<!--
Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
SPDX-License-Identifier: AGPL-3.0-only
-->
# Upgrading

How to move an **existing deployment** to a newer version without surprises.
Read this if your database predates the version you're deploying — especially if
you first ran the platform with a plain `docker compose up` (which bootstraps the
schema via the app's `ensure_schema()` fallback) instead of Alembic migrations.

> TL;DR — back up, then `alembic upgrade head`. If you've **never run Alembic**
> and you hit `column users.totp_secret does not exist`, jump to
> [§2 Adopting Alembic on a pre-Alembic database](#2-adopting-alembic-on-a-pre-alembic-database).

---

## 0. Always back up first

```bash
# adjust the compose file / creds to your deployment
docker compose -f infra/docker/docker-compose.prod.yml exec -T postgres \
  pg_dump -U "${POSTGRES_USER:-nis2}" "${POSTGRES_DB:-nis2}" > backup-$(date +%F).sql
```

A schema upgrade is hard to undo cleanly; the dump is your rollback.

---

## 1. The supported path: Alembic

The schema is versioned by Alembic (`packages/api/alembic/versions/`,
`001 → 006`). Pull the new code, rebuild, then apply migrations:

```bash
docker compose -f <your-compose-file> exec api alembic upgrade head
```

For a database that has **always** been managed by Alembic, this is all you need.

> **Always confirm the migration actually committed** — `alembic upgrade`/`stamp`
> log "Running …" *before* the write, so a successful-looking log is not proof:
>
> ```bash
> docker compose exec api alembic current        # must print the head revision (006…)
> docker compose exec postgres psql -U nis2 -d nis2 -c '\dt alembic_version'
> ```
>
> If `alembic current` prints nothing / the `alembic_version` table is absent, the
> command ran but did not persist (seen with some async-engine + container
> combinations). Re-run it directly in the API environment (`cd packages/api &&
> alembic upgrade head` with `DATABASE_URL` set) and re-check before continuing.

---

## 2. Adopting Alembic on a pre-Alembic database

Deployments first started with a bare `docker compose up` had their schema created
by `ensure_schema()` (a convenience fallback). That path **does not** record an
Alembic version and **does not** backfill columns added in later releases. The
giveaway:

> `asyncpg.exceptions.UndefinedColumnError: column users.totp_secret does not exist`
> — surfacing as **HTTP 500 on register / login**.

**Step 1 — which case are you in?**

```bash
docker compose exec postgres psql -U nis2 -d nis2 -tAc \
  "SELECT version_num FROM alembic_version"
#   prints a revision  -> already on Alembic; use §1
#   ERROR 'does not exist' -> never tracked; continue
```

**Step 2 — stamp the baseline you're at, then upgrade.** A database created before
the MFA / invite features sits at the RLS-policies baseline (`002`). Confirm
(expect **0 rows** = pre-MFA), then adopt and roll forward:

```bash
# confirm pre-MFA (no totp columns yet):
docker compose exec postgres psql -U nis2 -d nis2 -tAc \
  "SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='totp_secret'"

# tell Alembic you're at 002, then apply 003-006:
docker compose exec api alembic stamp 002_add_rls_policies
docker compose exec api alembic upgrade head
```

This applies the migrations you were missing — **003** (TOTP fields), **004**
(invite token), **005** (TOTP secret length), **006** (TOTP recovery codes) — and
clears the `UndefinedColumn` errors.

> ⚠️ Do **not** use `alembic stamp head` (or `make db-stamp`) on a drifted
> database — that records "fully migrated" while columns are still missing, and
> the errors persist. Stamp the revision your schema actually matches.

> If `alembic upgrade head` then fails with *"column already exists"*, your schema
> is an unusual partial mix (some later columns present, others not). Safest
> recovery: create a fresh database, `alembic upgrade head` from empty, and reload
> your data from the §0 backup (`--data-only` or selective `COPY`).

---

## 3. Enable enforced tenant isolation (RLS least-privilege role)

Tenant isolation is enforced by Postgres Row-Level Security, which is **bypassed**
for `SUPERUSER` / `BYPASSRLS` roles. If the app still connects as the bootstrap
superuser (`nis2`), the policies are decorative and isolation rests on the
application-layer `organization_id` filters alone — and in production the app logs
a startup warning about it.

To switch to the enforced model, provision the non-superuser `nis2_app` role and
point the API + worker at it. Full runbook, including the acceptance test that
proves isolation holds at the database:
**[`docs/h5-rls-validation.md`](docs/h5-rls-validation.md)** (ships with the
least-privilege role).

This is optional and can be done after the schema upgrade; nothing else depends
on it.

---

## 4. Verify

```bash
curl -s localhost:8000/api/v1/health          # -> {"status":"ok"}
docker compose exec api alembic current       # -> 006_add_totp_recovery_codes (head)
```

Then register / log in once and confirm the worker logs are clean. If you adopted
the `nis2_app` role, also run the isolation proof from §3's runbook.
