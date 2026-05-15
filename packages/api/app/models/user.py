# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.base import TimestampMixin

if TYPE_CHECKING:
    from app.models.membership import Membership


class User(TimestampMixin, Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(
        String(320), unique=True, index=True, nullable=False
    )
    password_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    full_name: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    avatar_url: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)

    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    locale: Mapped[str] = mapped_column(String(10), default="en", nullable=False)
    oauth_provider: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    oauth_provider_id: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)

    totp_secret: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    last_login_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # When the user last changed their password. Used as a watermark by
    # the JWT decode path: any access/refresh token whose `iat` predates
    # this timestamp is rejected, so a password change immediately
    # invalidates every other still-active session for this user without
    # tracking individual jtis. Nullable so legacy users (created before
    # this column existed) read as "never changed" — `iat is None or iat
    # >= None` is a no-op check.
    password_changed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    memberships: Mapped[list[Membership]] = relationship(
        "Membership",
        back_populates="user",
        lazy="selectin",
        foreign_keys="Membership.user_id",
    )

    def __repr__(self) -> str:
        return f"<User {self.email}>"
