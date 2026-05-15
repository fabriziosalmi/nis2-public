"""Add TOTP fields to users table — NIS2 Art. 21(j) MFA.

Revision ID: 002_add_totp_fields
Revises: 001_initial
Create Date: 2026-05-15

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "002_add_totp_fields"
down_revision: Union[str, None] = "001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Bypass RLS so the migration can touch the users table without a
    # tenant context (same pattern as env.py / auth router bootstrap).
    op.execute("SET LOCAL app.bypass_rls = 'on'")

    op.add_column(
        "users",
        sa.Column("totp_secret", sa.String(64), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column(
            "totp_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )


def downgrade() -> None:
    op.execute("SET LOCAL app.bypass_rls = 'on'")
    op.drop_column("users", "totp_enabled")
    op.drop_column("users", "totp_secret")
