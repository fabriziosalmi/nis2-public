"""Re-anchor the Art. 23 final-report deadline on the notification.

Revision ID: 009_final_report_anchor
Revises: 008_asset_verification

Art. 23(4)(d) requires the final report "not later than one month after the
submission of the incident notification referred to in point (b)" — the 72-hour
notification. The write path computed `detected_at + 30 days`, so every stored
deadline is three days early and the breach alert fires while the operator is
still inside the legal window.

Only rows carrying exactly the old formula are moved. A deadline that was
adjusted by hand, or written by some other path, is left alone: guessing at
someone else's correction would be worse than the bug.
"""

from typing import Sequence, Union

from alembic import op

revision: str = "009_final_report_anchor"
down_revision: Union[str, None] = "008_asset_verification"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        UPDATE incidents
           SET final_report_deadline = final_report_deadline + INTERVAL '72 hours'
         WHERE final_report_deadline = detected_at + INTERVAL '30 days'
        """
    )


def downgrade() -> None:
    op.execute(
        """
        UPDATE incidents
           SET final_report_deadline = final_report_deadline - INTERVAL '72 hours'
         WHERE final_report_deadline = detected_at + INTERVAL '30 days' + INTERVAL '72 hours'
        """
    )
