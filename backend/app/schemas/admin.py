"""backend/app/schemas/admin.py"""
from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel


class AdminUserView(BaseModel):
    id: int
    name: str
    username: str
    email: str
    role: str
    is_active: bool
    created_at: Any
    last_login: Optional[Any] = None
    scan_count: int = 0

    model_config = {"from_attributes": True}


class AuditEventResponse(BaseModel):
    id: int
    actor_user_id: Optional[int]
    actor_username: Optional[str] = None
    action: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    ip_address: Optional[str]
    metadata_: Optional[Dict[str, Any]] = None
    timestamp: datetime

    model_config = {"from_attributes": True}


class AuditEventListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[AuditEventResponse]


class ModelVersionAdminView(BaseModel):
    id: int
    version: str
    algorithm: Optional[str]
    training_date: Optional[datetime]
    deployment_status: str
    evaluation_summary: Optional[Dict[str, Any]]
    created_at: datetime

    model_config = {"from_attributes": True}


class UserListResponse(BaseModel):
    total: int
    items: List[AdminUserView]
