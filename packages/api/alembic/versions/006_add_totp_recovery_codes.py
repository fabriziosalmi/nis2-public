# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""Add totp_recovery_codes column to users table.

Revision ID: 006_add_totp_recovery_codes
Revises: 005_increase_totp_secret_length
Create Date: 2026-06-24

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "006_add_totp_recovery_codes"
down_revision: Union[str, None] = "005_increase_totp_secret_length"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Bypass RLS so the migration can alter the column structure
    op.execute("SET LOCAL app.bypass_rls = 'on'")
    op.add_column(
        "users",
        sa.Column("totp_recovery_codes", sa.String(length=1024), nullable=True),
    )


def downgrade() -> None:
    # Bypass RLS so the migration can alter the column structure
    op.execute("SET LOCAL app.bypass_rls = 'on'")
    op.drop_column("users", "totp_recovery_codes")
