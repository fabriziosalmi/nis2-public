# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""
Password-reset tokens (audit B05).

We store a sha256 hash of the token rather than the token itself so a
DB dump (or a LEFT JOIN against an audit log) can't be replayed to
reset accounts. The raw token is sent only by email; the user pastes
it back through the `/reset-password?token=...` URL and we hash it on
arrival to look up the row.

Table is intentionally NOT tenant-scoped: a forgot-password flow runs
before the user has selected an org (or even logged in), and the
target user may belong to multiple orgs anyway.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.base import TimestampMixin


class PasswordResetToken(TimestampMixin, Base):
    __tablename__ = "password_reset_tokens"
    __table_args__ = (
        # Prune by expiry — a periodic Celery task can sweep
        # `WHERE expires_at < now()` cheaply with this index.
        Index("ix_password_reset_tokens_expires_at", "expires_at"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # sha256 hex digest of the raw token (64 chars). Unique so a same
    # token can't be issued twice, and so we can do an O(log N) lookup.
    token_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    # Set to the consumption timestamp on first successful use so the
    # row reads as "spent" — single-use semantics. NULL = unused.
    used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:
        return f"<PasswordResetToken user_id={self.user_id} expires_at={self.expires_at}>"
