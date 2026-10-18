"""
backend/app/models/audit.py
----------------------------
AuditEvent table — immutable log of sensitive actions.
"""
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Text, JSON, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database.session import Base


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    actor_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # e.g. user.login | user.logout | scan.create | scan.delete |
    #      user.suspend | user.role_change | report.download | settings.update
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_: Mapped[dict | None] = mapped_column("metadata", JSON, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
        nullable=False, index=True
    )

    # Relationships
    actor: Mapped["User | None"] = relationship(
        "User", back_populates="audit_events", foreign_keys=[actor_user_id]
    )

    __table_args__ = (
        Index("ix_audit_events_action_ts", "action", "timestamp"),
    )

    def __repr__(self) -> str:
        return f"<AuditEvent action={self.action} actor={self.actor_user_id}>"
