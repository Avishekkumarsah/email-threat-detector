"""
backend/app/models/url.py
--------------------------
ExtractedURL table — normalized per-URL record per scan.
"""
from datetime import datetime, timezone
from sqlalchemy import String, Boolean, DateTime, Text, ForeignKey, JSON, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database.session import Base


class ExtractedURL(Base):
    __tablename__ = "extracted_urls"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("email_scans.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # URL details
    original_url: Mapped[str] = mapped_column(Text, nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    protocol: Mapped[str | None] = mapped_column(String(10), nullable=True)
    anchor_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str | None] = mapped_column(String(20), nullable=True)  # plain | html

    # Analysis results
    uses_https: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    is_ip_address: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    is_punycode: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    uses_shortener: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    has_anchor_mismatch: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    url_score: Mapped[int | None] = mapped_column(nullable=True)

    # Reputation check
    analysis_status: Mapped[str] = mapped_column(String(30), default="not_checked")
    # not_checked | checked | error | unavailable
    reputation_result: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # Flags JSON array
    flags: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # Relationships
    scan: Mapped["EmailScan"] = relationship("EmailScan", back_populates="extracted_urls")

    __table_args__ = (
        Index("ix_extracted_urls_scan_host", "scan_id", "hostname"),
    )

    def __repr__(self) -> str:
        return f"<ExtractedURL scan={self.scan_id} host={self.hostname}>"
