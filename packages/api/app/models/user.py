from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.dialects.postgresql import UUID
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

    last_login_at: Mapped[Optional[datetime]] = mapped_column(
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
