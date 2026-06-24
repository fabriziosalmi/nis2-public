# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""Increase totp_secret column length for encrypted TOTP secrets.

Revision ID: 005_increase_totp_secret_length
Revises: 004_add_invite_token
Create Date: 2026-06-24

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "005_increase_totp_secret_length"
down_revision: Union[str, None] = "004_add_invite_token"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Bypass RLS so the migration can alter the column structure
    op.execute("SET LOCAL app.bypass_rls = 'on'")
    op.alter_column(
        "users",
        "totp_secret",
        existing_type=sa.String(length=64),
        type_=sa.String(length=256),
        nullable=True,
    )


def downgrade() -> None:
    op.execute("SET LOCAL app.bypass_rls = 'on'")
    op.alter_column(
        "users",
        "totp_secret",
        existing_type=sa.String(length=256),
        type_=sa.String(length=64),
        nullable=True,
    )
