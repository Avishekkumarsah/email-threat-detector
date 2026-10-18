"""
backend/app/models/__init__.py
All SQLAlchemy models imported here for Alembic autogenerate.
"""
from backend.app.models.user import User
from backend.app.models.scan import EmailScan
from backend.app.models.finding import ScanFinding
from backend.app.models.url import ExtractedURL
from backend.app.models.model_version import ModelVersion
from backend.app.models.audit import AuditEvent
from backend.app.models.settings import ApplicationSetting
from backend.app.models.imap_credential import ImapCredential
from backend.app.models.password_reset import PasswordResetToken

__all__ = [
    "User",
    "EmailScan",
    "ScanFinding",
    "ExtractedURL",
    "ModelVersion",
    "AuditEvent",
    "ApplicationSetting",
    "ImapCredential",
    "PasswordResetToken",
]
