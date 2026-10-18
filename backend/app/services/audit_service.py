"""
backend/app/services/audit_service.py
---------------------------------------
Centralized audit event logging for all sensitive actions.
"""
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.orm import Session
from backend.app.models.audit import AuditEvent


def log_event(
    db: Session,
    action: str,
    actor_user_id: Optional[int] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> AuditEvent:
    """
    Create and persist an audit event.
    Never raises — audit failures are logged but don't break the request.
    """
    try:
        event = AuditEvent(
            actor_user_id=actor_user_id,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id is not None else None,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata_=metadata,
            timestamp=datetime.now(timezone.utc),
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event
    except Exception as e:
        db.rollback()
        print(f"[AUDIT] Failed to log event '{action}': {e}")
        return None
