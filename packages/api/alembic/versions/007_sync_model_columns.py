"""Sync model-only columns + widen under-sized types onto the migration baseline.

Revision ID: 007_sync_model_columns
Revises: 006_add_totp_recovery_codes
Create Date: 2026-06-27

Migrations 001-006 had drifted from the SQLAlchemy models: ~11 columns the models
define were never added by a migration (only by ensure_schema's create_all), and a
few VARCHAR columns were created narrower than the model. The drift was masked
because `alembic upgrade` never actually persisted until the env.py SET-LOCAL fix
that ships with this change — so the dev/prod schema was always built by
ensure_schema (create_all), not Alembic. This brings the Alembic schema in line
with the models for those columns.

Deliberately additive + conservative: it ADDs the missing columns and WIDENS the
under-sized types only. It does NOT touch existing unique constraints / indexes —
a raw `alembic revision --autogenerate` wanted to DROP the api_keys.key_hash,
uq_user_org and password_reset_tokens.token_hash UNIQUE constraints (because the
models express the same uniqueness under different names); those are
security-relevant and functionally correct as-is, so they are left untouched.
Narrowings are skipped too (a DB column wider than the model is harmless).
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "007_sync_model_columns"
down_revision: Union[str, None] = "006_add_totp_recovery_codes"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Columns defined on the models but never added by a migration. server_default
    # on the NOT NULL ones keeps ADD COLUMN safe on a populated table; it mirrors
    # the models' Python-side defaults (which fill new rows anyway).
    op.add_column("findings", sa.Column("scan_result_id", sa.UUID(), nullable=True))
    op.add_column("findings", sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("findings", sa.Column("occurrences", sa.Integer(), nullable=False, server_default="1"))
    op.add_column("memberships", sa.Column("invited_by", sa.UUID(), nullable=True))
    op.add_column("notification_channels", sa.Column("events", sa.ARRAY(sa.Text()), nullable=True))
    op.add_column("organizations", sa.Column("plan", sa.String(length=50), nullable=False, server_default="free"))
    op.add_column("organizations", sa.Column("max_scans_per_month", sa.Integer(), nullable=False, server_default="50"))
    op.add_column("users", sa.Column("avatar_url", sa.String(length=1024), nullable=True))
    op.add_column("users", sa.Column("oauth_provider", sa.String(length=50), nullable=True))
    op.add_column("users", sa.Column("oauth_provider_id", sa.String(length=256), nullable=True))
    op.add_column("users", sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True))

    # Widen columns the migrations created narrower than the models (else a
    # model-length value would be truncated/rejected on an Alembic-built DB).
    op.alter_column("api_keys", "name", existing_type=sa.VARCHAR(length=128), type_=sa.String(length=256))
    op.alter_column("findings", "compliance_article", existing_type=sa.VARCHAR(length=100), type_=sa.String(length=256))
    op.alter_column("notification_channels", "name", existing_type=sa.VARCHAR(length=128), type_=sa.String(length=256))
    op.alter_column("scans", "scan_type", existing_type=sa.VARCHAR(length=30), type_=sa.String(length=50))
    op.alter_column("users", "email", existing_type=sa.VARCHAR(length=256), type_=sa.String(length=320))

    # Columns the migrations created as JSONB but the models define as native
    # arrays. The ORM (ARRAY type) can't read/write a jsonb column → 500 on
    # api-key create + scan-result persistence. 007 only ever runs during a fresh
    # `alembic upgrade head` (001-006 insert no data, so these tables are empty
    # here), so a drop + re-add is clean — and PG can't cast jsonb→array in an
    # ALTER ... USING without a subquery anyway. incident_reports.report_data
    # (jsonb vs a JSON-typed model column) is left as-is — jsonb is a JSON drop-in.
    op.drop_column("api_keys", "scopes")
    op.add_column("api_keys", sa.Column("scopes", sa.ARRAY(sa.Text()), nullable=True))
    op.drop_column("scan_results", "errors")
    op.add_column("scan_results", sa.Column("errors", sa.ARRAY(sa.String()), nullable=True))
    op.drop_column("scan_results", "open_ports")
    op.add_column("scan_results", sa.Column("open_ports", sa.ARRAY(sa.Integer()), nullable=True))


def downgrade() -> None:
    op.drop_column("scan_results", "open_ports")
    op.add_column("scan_results", sa.Column("open_ports", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.drop_column("scan_results", "errors")
    op.add_column("scan_results", sa.Column("errors", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.drop_column("api_keys", "scopes")
    op.add_column("api_keys", sa.Column("scopes", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.alter_column("users", "email", existing_type=sa.String(length=320), type_=sa.VARCHAR(length=256))
    op.alter_column("scans", "scan_type", existing_type=sa.String(length=50), type_=sa.VARCHAR(length=30))
    op.alter_column("notification_channels", "name", existing_type=sa.String(length=256), type_=sa.VARCHAR(length=128))
    op.alter_column("findings", "compliance_article", existing_type=sa.String(length=256), type_=sa.VARCHAR(length=100))
    op.alter_column("api_keys", "name", existing_type=sa.String(length=256), type_=sa.VARCHAR(length=128))
    op.drop_column("users", "last_login_at")
    op.drop_column("users", "oauth_provider_id")
    op.drop_column("users", "oauth_provider")
    op.drop_column("users", "avatar_url")
    op.drop_column("organizations", "max_scans_per_month")
    op.drop_column("organizations", "plan")
    op.drop_column("notification_channels", "events")
    op.drop_column("memberships", "invited_by")
    op.drop_column("findings", "occurrences")
    op.drop_column("findings", "resolved_at")
    op.drop_column("findings", "scan_result_id")
