"""Asset ownership verification.

Revision ID: 008_asset_verification
Revises: 007_sync_model_columns

Adds proof that an organisation may scan a target. Until now there was none: any
authenticated user could add any domain or a /16 as an asset and have the
platform port-scan it, attempt zone transfers against its nameservers and
request /.env from it.

Existing rows are stamped `legacy` rather than `unverified`. The difference
matters: `unverified` blocks scanning, and an upgrade that silently stopped
every existing customer's scans would be its own defect. `legacy` keeps them
working while being visibly distinct from a target whose ownership was actually
proven — the UI shows it as unverified, and an operator who wants the strict
posture can require re-verification.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "008_asset_verification"
down_revision: Union[str, None] = "007_sync_model_columns"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "assets",
        sa.Column(
            "verification_status",
            sa.String(16),
            nullable=False,
            server_default="unverified",
        ),
    )
    op.add_column("assets", sa.Column("verification_token", sa.String(64), nullable=True))
    op.add_column(
        "assets",
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "assets",
        sa.Column("verified_by", sa.dialects.postgresql.UUID(as_uuid=True), nullable=True),
    )

    # Grandfather what already exists. Done as an UPDATE rather than a different
    # server_default so that rows created from here on start at `unverified`.
    op.execute("UPDATE assets SET verification_status = 'legacy'")


def downgrade() -> None:
    op.drop_column("assets", "verified_by")
    op.drop_column("assets", "verified_at")
    op.drop_column("assets", "verification_token")
    op.drop_column("assets", "verification_status")
