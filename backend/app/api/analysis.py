"""
backend/app/api/analysis.py
-----------------------------
Per-scan analysis endpoints: findings, URLs, PDF report.
"""
import os
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from typing import List, Optional

from backend.app.database.session import get_db
from backend.app.models.user import User
from backend.app.models.finding import ScanFinding
from backend.app.models.url import ExtractedURL
from backend.app.schemas.scan import ScanFindingResponse, ExtractedURLResponse
from backend.app.security.dependencies import get_current_user, get_scan_for_user
from backend.app.services.audit_service import log_event
from backend.app.core.config import get_settings

settings = get_settings()
router = APIRouter(prefix="/api/scans", tags=["Analysis"])


@router.get("/{scan_id}/findings", response_model=List[ScanFindingResponse])
def get_findings(
    scan_id: int,
    severity: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return all findings for a scan. Optionally filter by severity."""
    get_scan_for_user(scan_id, current_user, db)
    q = db.query(ScanFinding).filter(ScanFinding.scan_id == scan_id)
    if severity:
        q = q.filter(ScanFinding.severity == severity)
    return q.order_by(ScanFinding.points.desc()).all()


@router.get("/{scan_id}/urls", response_model=List[ExtractedURLResponse])
def get_urls(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return all extracted URLs for a scan."""
    get_scan_for_user(scan_id, current_user, db)
    return db.query(ExtractedURL).filter(ExtractedURL.scan_id == scan_id).all()


@router.get("/{scan_id}/report")
def download_report(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Generate and download a PDF forensic report for a scan."""
    scan = get_scan_for_user(scan_id, current_user, db)

    try:
        from backend.app.reports.pdf_report import generate_report
        pdf_path = generate_report(scan)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {e}")

    if not os.path.exists(pdf_path):
        raise HTTPException(status_code=500, detail="Report file was not created.")

    log_event(db, "report.download", actor_user_id=current_user.id,
              resource_type="scan", resource_id=scan_id)

    return FileResponse(
        path=pdf_path,
        filename=f"threat_report_{scan_id}.pdf",
        media_type="application/pdf",
    )
