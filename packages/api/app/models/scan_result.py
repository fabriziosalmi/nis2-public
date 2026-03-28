from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Optional

from sqlalchemy import ARRAY, Boolean, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.base import TimestampMixin

if TYPE_CHECKING:
    from app.models.scan import Scan


class ScanResult(TimestampMixin, Base):
    __tablename__ = "scan_results"
    __table_args__ = (Index("ix_scan_results_scan_id", "scan_id"),)

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    ip: Mapped[str] = mapped_column(String(45), nullable=False)
    is_alive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    open_ports: Mapped[Optional[list[int]]] = mapped_column(
        ARRAY(Integer), default=list, nullable=True
    )

    # Scan data sections
    http_info: Mapped[Optional[dict]] = mapped_column(JSONB, default=dict, nullable=True)
    tls_info: Mapped[Optional[dict]] = mapped_column(JSONB, default=dict, nullable=True)
    dns_info: Mapped[Optional[dict]] = mapped_column(JSONB, default=dict, nullable=True)
    legal_info: Mapped[Optional[dict]] = mapped_column(
        JSONB, default=dict, nullable=True
    )
    resilience_info: Mapped[Optional[dict]] = mapped_column(
        JSONB, default=dict, nullable=True
    )
    whois_info: Mapped[Optional[dict]] = mapped_column(
        JSONB, default=dict, nullable=True
    )
    secrets_found: Mapped[Optional[dict]] = mapped_column(
        JSONB, default=list, nullable=True
    )
    errors: Mapped[Optional[list[str]]] = mapped_column(
        ARRAY(String), default=list, nullable=True
    )

    # Relationships
    scan: Mapped[Scan] = relationship("Scan", back_populates="results")

    def __repr__(self) -> str:
        return f"<ScanResult {self.target} ({self.ip})>"
