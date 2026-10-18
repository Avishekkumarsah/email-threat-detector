"""
backend/app/models/scan.py
---------------------------
EmailScan table — one row per scan, referencing model version.
Full email body NOT stored by default (opt-in via store_body flag).
"""
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Float, DateTime, Text, ForeignKey, Boolean, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database.session import Base


class EmailScan(Base):
    __tablename__ = "email_scans"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    model_version_id: Mapped[int | None] = mapped_column(
        ForeignKey("model_versions.id", ondelete="SET NULL"), nullable=True
    )

    # Status
    scan_status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="completed"
    )  # pending | processing | completed | failed

    # Email metadata
    original_filename: Mapped[str | None] = mapped_column(String(512), nullable=True)
    file_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    subject: Mapped[str | None] = mapped_column(Text, nullable=True)
    sender: Mapped[str | None] = mapped_column(Text, nullable=True)
    reply_to: Mapped[str | None] = mapped_column(Text, nullable=True)
    received_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Classification results
    classification: Mapped[str | None] = mapped_column(String(30), nullable=True)
    # Likely Legitimate | Suspicious | Likely Phishing | Insufficient Evidence
    model_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    overall_risk: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # Low Risk | Medium Risk | High Risk | Critical Risk | Inconclusive
    scoring_rule_version: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # Full result as JSON (for backward compat + report generation)
    full_result_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Optional full body storage (opt-in)
    store_body: Mapped[bool] = mapped_column(Boolean, default=False)
    email_body_plain: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Error info
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    user: Mapped["User | None"] = relationship("User", back_populates="scans")
    model_version: Mapped["ModelVersion | None"] = relationship("ModelVersion", back_populates="scans")
    findings: Mapped[list["ScanFinding"]] = relationship(
        "ScanFinding", back_populates="scan", cascade="all, delete-orphan"
    )
    extracted_urls: Mapped[list["ExtractedURL"]] = relationship(
        "ExtractedURL", back_populates="scan", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_email_scans_user_created", "user_id", "created_at"),
        Index("ix_email_scans_overall_risk", "overall_risk"),
    )

    def __repr__(self) -> str:
        return f"<EmailScan id={self.id} risk={self.overall_risk} user={self.user_id}>"
