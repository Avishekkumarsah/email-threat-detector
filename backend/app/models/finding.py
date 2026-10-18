"""
backend/app/models/finding.py
------------------------------
ScanFinding table — normalized per-finding rows (not JSON blob).
"""
from datetime import datetime, timezone
from sqlalchemy import String, Float, DateTime, Text, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database.session import Base


class ScanFinding(Base):
    __tablename__ = "scan_findings"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("email_scans.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Finding classification
    finding_type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    # low | medium | high | critical

    # Human-readable details
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # content | header | url | attachment | geo | authentication

    # Confidence and scoring
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    points: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Recommended action for user
    recommended_action: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # Relationships
    scan: Mapped["EmailScan"] = relationship("EmailScan", back_populates="findings")

    __table_args__ = (
        Index("ix_scan_findings_scan_severity", "scan_id", "severity"),
    )

    def __repr__(self) -> str:
        return f"<ScanFinding scan={self.scan_id} type={self.finding_type} sev={self.severity}>"
