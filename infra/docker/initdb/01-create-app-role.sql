-- ============================================================================
-- H5: least-privilege application DB role.
-- ============================================================================
-- The platform's tenant isolation is Postgres Row-Level Security. RLS policies
-- are BYPASSED for SUPERUSER / BYPASSRLS roles, so if the API + worker connect
-- as the bootstrap superuser (the default `nis2` in the postgres image) the
-- policies are decorative — isolation rests on app-layer org_id filters only.
--
-- This script provisions a NOSUPERUSER NOBYPASSRLS role the policies actually
-- apply to. Point the API + worker DATABASE_URL at it; keep the bootstrap
-- superuser for migrations only.
--
-- HOW TO APPLY
--   Fresh deploy: drop this file in the postgres container's
--     /docker-entrypoint-initdb.d/ (runs once, on first volume init).
--   Existing deploy (volume already initialised): run it once manually as the
--     superuser, e.g.
--       psql "$SUPERUSER_DATABASE_URL" -v app_pw="$NIS2_APP_PASSWORD" \
--            -f 01-create-app-role.sql
--
-- Requires the psql variable `app_pw` (the new role's password). With the
-- docker-entrypoint-initdb.d path, set it via a tiny wrapper that exports it as
-- a psql var, or replace :'app_pw' with the value at deploy time.
-- ============================================================================

\set ON_ERROR_STOP on

-- 1. The role (idempotent). psql does NOT interpolate :'app_pw' inside a
--    dollar-quoted DO block, so build the CREATE statement in plain SQL (where
--    psql DOES substitute the variable) and run it with \gexec. WHERE NOT EXISTS
--    makes it a no-op when the role already exists.
SELECT format(
  'CREATE ROLE nis2_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD %L',
  :'app_pw'
)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nis2_app')
\gexec

-- 2. DML (no DDL) on the current schema + everything migrations create later.
GRANT USAGE ON SCHEMA public TO nis2_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO nis2_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO nis2_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO nis2_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO nis2_app;

-- 3. (M2 — append-only audit log) ENFORCED at app boot in
--    app.database.setup_row_level_security, NOT here. Both the REVOKE and the
--    purge helper reference audit_logs, which does not exist yet on first volume
--    init (the app builds the schema on its first boot). setup_row_level_security
--    — run as the superuser/migration role — creates a SECURITY DEFINER
--    purge_old_audit_logs() function, restricts its EXECUTE to nis2_app, then
--    runs `REVOKE UPDATE, DELETE ON audit_logs FROM nis2_app`. cleanup_tasks
--    calls that function so the retention purge keeps working under the
--    append-only role (it bypasses RLS and keeps DELETE as the definer).
