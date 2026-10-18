"""
backend/app/schemas/__init__.py
"""
from backend.app.schemas.auth import (
    RegisterRequest, LoginRequest, TokenResponse, RefreshRequest,
    UserResponse, UserUpdateRequest
)
from backend.app.schemas.scan import (
    ScanSummary, ScanDetailResponse, ScanListResponse,
    AnalyzeSourceRequest, ScanFindingResponse, ExtractedURLResponse
)
from backend.app.schemas.dashboard import DashboardSummary, TrendPoint, DashboardTrends
from backend.app.schemas.model import ModelStatusResponse, ModelMetricsResponse
from backend.app.schemas.admin import (
    AdminUserView, AuditEventResponse, ModelVersionAdminView
)
from backend.app.schemas.settings import SettingResponse, SettingPatchRequest
