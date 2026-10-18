"""backend/app/api/admin.py — Admin-only endpoints"""
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session
from typing import List, Optional

from backend.app.database.session import get_db
from backend.app.models.user import User
from backend.app.models.audit import AuditEvent
from backend.app.models.model_version import ModelVersion
from backend.app.schemas.admin import (
    AdminUserView, AuditEventResponse, ModelVersionAdminView,
    AuditEventListResponse, UserListResponse
)
from backend.app.security.dependencies import require_admin
from backend.app.services.audit_service import log_event

router = APIRouter(prefix="/api/admin", tags=["Admin"])


@router.get("/users", response_model=UserListResponse)
def list_users(admin=Depends(require_admin), db: Session = Depends(get_db)):
    from sqlalchemy import func
    from backend.app.models.scan import EmailScan
    users = db.query(User).order_by(User.created_at.desc()).all()
    items = []
    for u in users:
        count = db.query(EmailScan).filter(EmailScan.user_id == u.id).count()
        items.append(AdminUserView(
            id=u.id, name=u.name, username=u.username, email=u.email,
            role=u.role, is_active=u.is_active, created_at=u.created_at,
            last_login=u.last_login, scan_count=count,
        ))
    return UserListResponse(total=len(items), items=items)


@router.post("/users/{user_id}/toggle-role", status_code=200)
def toggle_role(
    user_id: int, request: Request,
    admin=Depends(require_admin), db: Session = Depends(get_db)
):
    if user_id == admin.id:
        raise HTTPException(400, "Cannot modify your own role.")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found.")
    user.role = "user" if user.role == "admin" else "admin"
    db.commit()
    log_event(db, "user.role_change", actor_user_id=admin.id,
              resource_type="user", resource_id=user_id,
              ip_address=request.client.host,
              metadata={"new_role": user.role})
    return {"id": user.id, "role": user.role}


@router.post("/users/{user_id}/suspend", status_code=204)
def suspend_user(
    user_id: int, request: Request,
    admin=Depends(require_admin), db: Session = Depends(get_db)
):
    if user_id == admin.id:
        raise HTTPException(400, "Cannot suspend yourself.")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found.")
    user.is_active = False
    db.commit()
    log_event(db, "user.suspend", actor_user_id=admin.id,
              resource_type="user", resource_id=user_id,
              ip_address=request.client.host)


@router.post("/users/{user_id}/activate", status_code=204)
def activate_user(
    user_id: int, request: Request,
    admin=Depends(require_admin), db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found.")
    user.is_active = True
    db.commit()
    log_event(db, "user.activate", actor_user_id=admin.id,
              resource_type="user", resource_id=user_id,
              ip_address=request.client.host)


@router.delete("/users/{user_id}", status_code=204)
def delete_user(
    user_id: int, request: Request,
    admin=Depends(require_admin), db: Session = Depends(get_db)
):
    if user_id == admin.id:
        raise HTTPException(400, "Cannot delete yourself.")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found.")
    db.delete(user)
    db.commit()
    log_event(db, "user.delete", actor_user_id=admin.id,
              resource_type="user", resource_id=user_id,
              ip_address=request.client.host)


@router.get("/audit-events", response_model=AuditEventListResponse)
def get_audit_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    action: Optional[str] = Query(None),
    admin=Depends(require_admin),
    db: Session = Depends(get_db),
):
    q = db.query(AuditEvent)
    if action:
        q = q.filter(AuditEvent.action.ilike(f"%{action}%"))
    total = q.count()
    events = q.order_by(AuditEvent.timestamp.desc()).offset((page - 1) * page_size).limit(page_size).all()
    items = []
    for e in events:
        actor_username = None
        if e.actor_user_id:
            u = db.query(User).filter(User.id == e.actor_user_id).first()
            actor_username = u.username if u else None
        items.append(AuditEventResponse(
            id=e.id, actor_user_id=e.actor_user_id, actor_username=actor_username,
            action=e.action, resource_type=e.resource_type, resource_id=e.resource_id,
            ip_address=e.ip_address, metadata_=e.metadata_, timestamp=e.timestamp,
        ))
    return AuditEventListResponse(total=total, page=page, page_size=page_size, items=items)


@router.get("/model-versions", response_model=List[ModelVersionAdminView])
def list_model_versions(admin=Depends(require_admin), db: Session = Depends(get_db)):
    versions = db.query(ModelVersion).order_by(ModelVersion.created_at.desc()).all()
    return [ModelVersionAdminView.model_validate(v) for v in versions]
