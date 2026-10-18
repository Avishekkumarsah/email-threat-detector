"""
backend/app/models/model_version.py
-------------------------------------
ModelVersion table — tracks trained ML artifacts.
"""
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Text, JSON, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database.session import Base


class ModelVersion(Base):
    __tablename__ = "model_versions"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    version: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    artifact_reference: Mapped[str | None] = mapped_column(Text, nullable=True)
    vectorizer_reference: Mapped[str | None] = mapped_column(Text, nullable=True)
    dataset_reference: Mapped[str | None] = mapped_column(Text, nullable=True)
    algorithm: Mapped[str | None] = mapped_column(String(100), nullable=True)
    training_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    evaluation_summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    deployment_status: Mapped[str] = mapped_column(String(20), default="inactive")
    # active | inactive | retired
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # Relationships
    scans: Mapped[list["EmailScan"]] = relationship("EmailScan", back_populates="model_version")

    def __repr__(self) -> str:
        return f"<ModelVersion v={self.version} status={self.deployment_status}>"
