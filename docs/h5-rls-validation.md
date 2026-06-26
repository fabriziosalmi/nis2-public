# H5 — validating RLS under a least-privilege DB role

The platform's tenant isolation is Postgres Row-Level Security. RLS is **bypassed**
for `SUPERUSER` / `BYPASSRLS` roles, so while the app connects as the bootstrap
superuser (`nis2`) the policies are decorative — isolation rests on the app-layer
`organization_id` filters alone. This runbook switches the app + worker to a
`NOSUPERUSER NOBYPASSRLS` role so the policies actually apply, and validates it.

> **Status of the H5 stack when you run this**
> - **Done & safe to validate now:** manual scans (PR #155) and report generation
>   (PR #158) set the worker's RLS org context before their tenant reads.
> - **WIP — expect breakage until the later chunks land** (tracked on #140):
>   *scheduled* scans (the beat sweep isn't org-looped yet) and *API-key* auth
>   (the `api_keys` lookup isn't RLS-exempt yet). Validate the **manual scan +
>   report** path first; don't cut scheduled/API-key traffic over until those land.

## 1. Provision the role

Fresh deploy: drop [`infra/docker/initdb/01-create-app-role.sql`](../infra/docker/initdb/01-create-app-role.sql)
into the postgres container's `/docker-entrypoint-initdb.d/` (runs once on first
volume init).

Existing deploy (volume already initialised): run it once as the superuser —

```bash
psql "$SUPERUSER_DATABASE_URL" -v app_pw="$NIS2_APP_PASSWORD" \
     -f infra/docker/initdb/01-create-app-role.sql
```

Confirm the role is least-privilege:

```sql
SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'nis2_app';
-- expect: f | f
```

## 2. Point the app + worker at the role (keep the superuser for migrations)

DDL (migrations) still needs the superuser — `nis2_app` has DML only. Keep two URLs:

```bash
# .env
SUPERUSER_DATABASE_URL=postgresql+asyncpg://nis2:<su_pw>@db:5432/nis2      # migrations only
DATABASE_URL=postgresql+asyncpg://nis2_app:<app_pw>@db:5432/nis2          # api + worker
```

Run migrations as the superuser, then start the app on the app role:

```bash
DATABASE_URL="$SUPERUSER_DATABASE_URL" alembic upgrade head
docker compose -f infra/docker/docker-compose.prod.yml up -d   # api/worker/beat read DATABASE_URL
```

The worker boot guard (`assert_db_role_rls_safe`) and the API lifespan should now
start **without** the "rolsuper/rolbypassrls — RLS bypassed" warning. If you see
`Refusing to start: ... SUPERUSER/BYPASSRLS app role`, the app is still on the
superuser URL.

## 3. Acceptance test

The point is to prove isolation holds **even with the app-layer filters removed** —
i.e. the database itself refuses cross-tenant reads.

1. **Manual scan persists (part 1).** Trigger a scan in org A from the UI/API. It
   must reach `completed` with findings. If findings come back empty / the scan
   stalls in `running`, `set_rls_org_context` isn't taking effect — check the
   worker connects as `nis2_app` and `CELERY_WORKER=1` is set (NullPool).
2. **Report generates (part 2).** Download a report for that scan → non-empty.
3. **Cross-tenant read is refused at the DB.** As `nis2_app` in psql, simulate org
   A's context and confirm org B's rows are invisible:

   ```sql
   SELECT set_config('app.current_org_id', '<ORG_A_UUID>', false);
   SELECT count(*) FROM scans;                          -- only org A's scans
   SELECT count(*) FROM scans WHERE organization_id = '<ORG_B_UUID>';  -- expect 0
   ```

   0 rows for org B is the proof RLS is doing the work, not just the API.

## 4. Rollback

Point `DATABASE_URL` back at the superuser URL and restart. Nothing in the schema
changed, so this is instant and lossless.

## What to report back

Per the acceptance test: do manual scans + reports work under `nis2_app`, and does
psql confirm 0 cross-tenant rows? Anything that breaks (especially scheduled scans
or API-key auth) is expected until the remaining #140 chunks land — note which, so
the per-org sweep / `api_keys` exemption can be prioritised.
