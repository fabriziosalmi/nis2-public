"""Add tenant-isolation RLS policies for all tenant-scoped tables.

Previously, RLS policies were created idempotently at every API startup
by setup_row_level_security() in lifespan(). Moving them here ensures:
  - A fresh DB has RLS from the moment 'alembic upgrade head' completes,
    before the API ever starts (closes the crash-window gap).
  - A partial startup cannot leave the DB with some tables unprotected.
  - Policy creation is auditable and version-controlled.

Revision ID: 002_add_rls_policies
Revises: 001_initial
Create Date: 2026-05-15

"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "002_add_rls_policies"
down_revision: Union[str, None] = "001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Hardcoded list of tenant-scoped tables (those with an organization_id column).
# Do NOT use SQLAlchemy metadata introspection here — that would create a
# dependency on the running model state rather than the DB state at migration time.
TENANT_TABLES: list[str] = [
    "api_keys",
    "assets",
    "audit_logs",
    "business_processes",
    "findings",
    "incidents",
    "memberships",
    "notification_channels",
    "scan_schedules",
    "scans",
    "vendors",
]

RLS_PREDICATE = (
    "(organization_id::text = current_setting('app.current_org_id', true) "
    "OR (current_setting('app.current_user_id', true) IS NOT NULL AND "
    "organization_id::text IN (SELECT organization_id::text FROM memberships WHERE user_id::text = current_setting('app.current_user_id', true))))"
)

RLS_MEMBERSHIPS_PREDICATE = (
    "(organization_id::text = current_setting('app.current_org_id', true) "
    "OR user_id::text = current_setting('app.current_user_id', true))"
)


def upgrade() -> None:
    for t in TENANT_TABLES:
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        predicate = RLS_MEMBERSHIPS_PREDICATE if t == "memberships" else RLS_PREDICATE
        op.execute(
            f"CREATE POLICY tenant_isolation ON {t} "
            f"USING {predicate} "
            f"WITH CHECK {predicate}"
        )


def downgrade() -> None:
    for t in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t}")
        op.execute(f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")
