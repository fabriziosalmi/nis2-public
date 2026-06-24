"""Add invite_token_hash and invite_token_expires_at to users.

Security fix: the accept-invite endpoint previously required only the
invitee's email — an attacker who knew/guessed the email of an invited
(inactive) user could set their password and take over the account.

This migration adds two columns that support cryptographic invite
tokens:
  - invite_token_hash: SHA-256 hash of the raw token (the raw token
    is sent to the invitee; only the hash is stored)
  - invite_token_expires_at: expiry timestamp (48 hours by default)

Revision ID: 004_add_invite_token
Revises: 003_add_totp_fields
Create Date: 2026-06-24

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "004_add_invite_token"
down_revision: Union[str, None] = "003_add_totp_fields"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Bypass RLS so the migration can touch the users table without a
    # tenant context (same pattern as 003_add_totp_fields).
    op.execute("SET LOCAL app.bypass_rls = 'on'")

    op.add_column(
        "users",
        sa.Column("invite_token_hash", sa.String(128), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column(
            "invite_token_expires_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.execute("SET LOCAL app.bypass_rls = 'on'")
    op.drop_column("users", "invite_token_expires_at")
    op.drop_column("users", "invite_token_hash")
