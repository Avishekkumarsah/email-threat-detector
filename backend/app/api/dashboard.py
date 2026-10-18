"""backend/app/api/dashboard.py"""
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.app.database.session import get_db
from backend.app.models.user import User
from backend.app.models.scan import EmailScan
from backend.app.models.finding import ScanFinding
from typing import Optional
from backend.app.schemas.dashboard import DashboardSummary, DashboardTrends, TrendPoint
from backend.app.security.dependencies import get_current_user_optional
from backend.app.ml.inference import get_model_status
from backend.app.core.config import get_settings

settings = get_settings()
router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/summary", response_model=DashboardSummary)
def dashboard_summary(
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    """Dashboard statistics from PostgreSQL. Shows personal stats if logged in as user, or system-wide stats if guest/admin."""
    if current_user and not current_user.is_admin:
        base = db.query(EmailScan).filter(EmailScan.user_id == current_user.id)
    else:
        # Public guest or Admin sees global aggregate metrics across all scans
        base = db.query(EmailScan)

    total_scans = base.count()
    likely_phishing = base.filter(EmailScan.classification == "Likely Phishing").count()
    suspicious = base.filter(EmailScan.classification == "Suspicious").count()
    likely_legitimate = base.filter(EmailScan.classification == "Likely Legitimate").count()
    insufficient = base.filter(EmailScan.classification == "Insufficient Evidence").count()

    # High/critical risk findings count via fast join
    if current_user and not current_user.is_admin:
        high_risk_findings = (
            db.query(func.count(ScanFinding.id))
            .join(EmailScan, ScanFinding.scan_id == EmailScan.id)
            .filter(EmailScan.user_id == current_user.id, ScanFinding.severity.in_(["high", "critical"]))
            .scalar() or 0
        )
    else:
        high_risk_findings = (
            db.query(func.count(ScanFinding.id))
            .filter(ScanFinding.severity.in_(["high", "critical"]))
            .scalar() or 0
        )

    # Recent scans
    recent = base.order_by(EmailScan.created_at.desc()).limit(5).all()
    recent_list = [
        {
            "id": s.id,
            "subject": s.subject or "(no subject)",
            "sender": s.sender or "Unknown",
            "overall_risk": s.overall_risk,
            "classification": s.classification,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in recent
    ]

    model_info = get_model_status()

    return DashboardSummary(
        total_scans=total_scans,
        likely_phishing=likely_phishing,
        suspicious=suspicious,
        likely_legitimate=likely_legitimate,
        insufficient_evidence=insufficient,
        high_risk_findings=high_risk_findings,
        model_version=model_info.get("version"),
        model_status=model_info.get("status", "unknown"),
        recent_scans=recent_list,
    )


@router.get("/trends", response_model=DashboardTrends)
def dashboard_trends(
    days: int = Query(30, ge=1, le=365),
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    """Scan activity trend over the last N days."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    if current_user and not current_user.is_admin:
        query = db.query(EmailScan).filter(
            EmailScan.user_id == current_user.id,
            EmailScan.created_at >= since,
        )
    else:
        query = db.query(EmailScan).filter(
            EmailScan.created_at >= since,
        )
    scans = query.all()

    # Group by date
    trend_map: dict = {}
    for s in scans:
        d = s.created_at.date().isoformat()
        if d not in trend_map:
            trend_map[d] = {"total": 0, "phishing": 0, "legitimate": 0, "suspicious": 0}
        trend_map[d]["total"] += 1
        if s.classification == "Likely Phishing":
            trend_map[d]["phishing"] += 1
        elif s.classification == "Likely Legitimate":
            trend_map[d]["legitimate"] += 1
        elif s.classification == "Suspicious":
            trend_map[d]["suspicious"] += 1

    data = [
        TrendPoint(date=d, total=v["total"], phishing=v["phishing"],
                   legitimate=v["legitimate"], suspicious=v["suspicious"])
        for d, v in sorted(trend_map.items())
    ]
    return DashboardTrends(period_days=days, data=data)
