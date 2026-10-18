"""
backend/app/api/scans.py
--------------------------
Scan endpoints: upload .eml, analyze pasted source, list, get, delete.
"""
import os
import uuid
import tempfile
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query, Request, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.models.user import User
from backend.app.models.scan import EmailScan
from backend.app.schemas.scan import (
    ScanSummary, ScanDetailResponse, ScanListResponse, AnalyzeSourceRequest
)
from backend.app.security.dependencies import get_current_user, get_scan_for_user
from backend.app.services.scan_service import run_scan_from_file, run_scan_from_source
from backend.app.services.audit_service import log_event
from backend.app.core.config import get_settings
import json

settings = get_settings()
router = APIRouter(prefix="/api/scans", tags=["Scans"])

MAX_BYTES = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024


def _scan_to_detail(scan: EmailScan) -> ScanDetailResponse:
    full_result = None
    if scan.full_result_json:
        try:
            full_result = json.loads(scan.full_result_json)
        except Exception:
            pass
    return ScanDetailResponse(
        id=scan.id,
        scan_status=scan.scan_status,
        original_filename=scan.original_filename,
        file_hash=scan.file_hash,
        subject=scan.subject,
        sender=scan.sender,
        reply_to=scan.reply_to,
        received_at=scan.received_at,
        classification=scan.classification,
        model_score=scan.model_score,
        overall_risk=scan.overall_risk,
        scoring_rule_version=scan.scoring_rule_version,
        error_message=scan.error_message,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
        findings=[
            {
                "id": f.id, "finding_type": f.finding_type, "severity": f.severity,
                "explanation": f.explanation, "evidence": f.evidence, "source": f.source,
                "confidence": f.confidence, "points": f.points,
                "recommended_action": f.recommended_action,
            }
            for f in scan.findings
        ],
        extracted_urls=[
            {
                "id": u.id, "original_url": u.original_url, "hostname": u.hostname,
                "protocol": u.protocol, "anchor_text": u.anchor_text, "source": u.source,
                "uses_https": u.uses_https, "is_ip_address": u.is_ip_address,
                "is_punycode": u.is_punycode, "uses_shortener": u.uses_shortener,
                "has_anchor_mismatch": u.has_anchor_mismatch, "url_score": u.url_score,
                "analysis_status": u.analysis_status, "reputation_result": u.reputation_result,
                "flags": u.flags, "checked_at": u.checked_at,
            }
            for u in scan.extracted_urls
        ],
        full_result=full_result,
    )


@router.post("/upload", response_model=ScanDetailResponse, status_code=status.HTTP_201_CREATED)
async def upload_scan(
    request: Request,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Upload a .eml or .txt email file for analysis."""
    # Validate extension
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"Only {settings.ALLOWED_EXTENSIONS} files are accepted.")

    # Read and check size
    content = await file.read()
    if len(content) > MAX_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size is {settings.MAX_UPLOAD_SIZE_MB} MB.",
        )
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    # Write to temp file
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    temp_name = f"{uuid.uuid4().hex}{ext}"
    temp_path = os.path.join(settings.UPLOAD_DIR, temp_name)
    try:
        with open(temp_path, "wb") as f:
            f.write(content)
        scan = run_scan_from_file(db, temp_path, file.filename, current_user.id)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

    log_event(db, "scan.create", actor_user_id=current_user.id,
              resource_type="scan", resource_id=scan.id,
              ip_address=request.client.host,
              metadata={"filename": file.filename, "risk": scan.overall_risk})

    db.refresh(scan)
    return _scan_to_detail(scan)


@router.post("/analyze-source", response_model=ScanDetailResponse, status_code=status.HTTP_201_CREATED)
def analyze_source(
    request: Request,
    body: AnalyzeSourceRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Analyze pasted raw email source (headers + body)."""
    if not body.raw_email or len(body.raw_email.strip()) < 10:
        raise HTTPException(status_code=400, detail="Email source is too short to analyze.")
    if len(body.raw_email) > MAX_BYTES:
        raise HTTPException(status_code=413, detail="Email source exceeds size limit.")

    scan = run_scan_from_source(db, body.raw_email, current_user.id)
    log_event(db, "scan.create", actor_user_id=current_user.id,
              resource_type="scan", resource_id=scan.id,
              ip_address=request.client.host,
              metadata={"source": "paste", "risk": scan.overall_risk})
    db.refresh(scan)
    return _scan_to_detail(scan)


@router.get("", response_model=ScanListResponse)
def list_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: Optional[str] = Query(None),
    risk: Optional[str] = Query(None),
    classification: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List scans for the authenticated user with pagination, search, and filters."""
    q = db.query(EmailScan).filter(EmailScan.user_id == current_user.id)

    if search:
        q = q.filter(
            EmailScan.subject.ilike(f"%{search}%")
            | EmailScan.sender.ilike(f"%{search}%")
            | EmailScan.original_filename.ilike(f"%{search}%")
        )
    if risk:
        q = q.filter(EmailScan.overall_risk == risk)
    if classification:
        q = q.filter(EmailScan.classification == classification)

    total = q.count()
    scans = q.order_by(EmailScan.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()

    return ScanListResponse(
        total=total, page=page, page_size=page_size,
        items=[ScanSummary.model_validate(s) for s in scans],
    )


@router.get("/{scan_id}", response_model=ScanDetailResponse)
def get_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = get_scan_for_user(scan_id, current_user, db)
    return _scan_to_detail(scan)


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(
    scan_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = get_scan_for_user(scan_id, current_user, db)
    db.delete(scan)
    db.commit()
    log_event(db, "scan.delete", actor_user_id=current_user.id,
              resource_type="scan", resource_id=scan_id,
              ip_address=request.client.host)
