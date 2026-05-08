# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Refresh-token revocation list.

We mint a unique `jti` claim for every refresh token. /logout adds the
current jti here; /refresh rotates by adding the OLD jti and minting a
new pair. Any subsequent reuse of the old refresh token (replay or
stolen-token reuse) hits the revocation list and is rejected.

Rows are kept until `expires_at`; the `cleanup_expired_auth_records`
Celery beat task (v2.5.1, see `cleanup_tasks.py`) prunes expired rows
hourly. The index on `expires_at` keeps both lookups and deletes O(log N).
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Index, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.base import TimestampMixin


class RevokedToken(TimestampMixin, Base):
    __tablename__ = "revoked_tokens"
    __table_args__ = (
        Index("ix_revoked_tokens_expires_at", "expires_at"),
    )

    # jti is a UUID4 string emitted by app.utils.jwt.create_refresh_token.
    # Unique across the table so /refresh can do a single keyed lookup.
    jti: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    # Mirrors the JWT exp claim so we can prune expired rows safely.
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Optional bookkeeping — useful for forensic audit of "who logged out".
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True, index=True
    )
    reason: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    def __repr__(self) -> str:
        return f"<RevokedToken jti={self.jti[:8]}…>"
