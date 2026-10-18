"""
backend/app/api/monitor_api.py
--------------------------------
FastAPI routes for real-time IMAP mailbox monitoring.
Integrates directly with modules/inbox_monitor.py.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from typing import Optional, List, Dict, Any
import os
import uuid
import logging
from datetime import datetime, timezone

from backend.app.database.session import get_db, SessionLocal
from backend.app.models.user import User
from backend.app.models.imap_credential import ImapCredential
from backend.app.security.dependencies import get_current_user
from backend.app.services.scan_service import run_scan_from_file
import config
from modules import inbox_monitor, database

logger = logging.getLogger("email_threat_api.monitor")
router = APIRouter(prefix="/api/monitor", tags=["Live Monitor"])


class ImapCredentialInput(BaseModel):
    imap_host: str = "imap.gmail.com"
    imap_port: int = 993
    imap_email: EmailStr
    app_password: str
    is_active: bool = True


class TestConnectionInput(BaseModel):
    imap_host: str = "imap.gmail.com"
    imap_port: int = 993
    imap_email: EmailStr
    app_password: str


def process_incoming_email(raw_bytes: bytes, user_id: int):
    """
    Callback invoked by inbox_monitor when a new email arrives over IMAP.
    Runs the forensic scan pipeline and records the result in both PostgreSQL
    and inbox_monitor's in-memory live feed.
    """
    logger.info(f"Processing real-time email from IMAP for user {user_id}")
    db = SessionLocal()
    temp_path = None
    try:
        temp_name = f"imap_{uuid.uuid4().hex}.eml"
        temp_path = os.path.join(config.UPLOAD_DIR, temp_name)
        os.makedirs(config.UPLOAD_DIR, exist_ok=True)
        with open(temp_path, "wb") as f:
            f.write(raw_bytes)

        scan = run_scan_from_file(
            db=db,
            file_path=temp_path,
            original_filename=temp_name,
            user_id=user_id,
        )

        inbox_monitor.record_scan(
            subject=scan.subject,
            sender=scan.sender,
            verdict=scan.classification or "Analyzed",
            scan_id=scan.id,
            user_id=user_id,
        )
        logger.info(f"Real-time email scanned: ID={scan.id}, Subject='{scan.subject}', Risk={scan.overall_risk}")
    except Exception as e:
        logger.error(f"Error processing real-time IMAP email: {e}", exc_info=True)
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass
        db.close()


@router.get("/status")
def get_monitor_status(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Return the current user's live monitoring status and feed."""
    status_data = inbox_monitor.get_status(current_user.id)
    imap_cred = db.query(ImapCredential).filter(ImapCredential.user_id == current_user.id).first()
    
    return {
        **status_data,
        "has_credentials": imap_cred is not None,
        "imap_email": imap_cred.imap_email if imap_cred else None,
        "imap_host": imap_cred.imap_host if imap_cred else None,
        "imap_port": imap_cred.imap_port if imap_cred else 993,
        "credentials_active": imap_cred.is_active if imap_cred else False,
        "poll_interval": config.POLL_INTERVAL_SECONDS,
    }


@router.post("/start")
def start_monitor(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Start background IMAP polling for the current user."""
    imap_cred = db.query(ImapCredential).filter(ImapCredential.user_id == current_user.id).first()
    if not imap_cred:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Configure your IMAP credentials first before starting live monitoring.",
        )

    imap_cred.is_active = True
    db.commit()

    started = inbox_monitor.start_monitoring_user(current_user.id, process_incoming_email)
    return {
        "success": True,
        "message": "Live monitoring started." if started else "Monitoring is already active.",
        "running": True,
    }


@router.post("/stop")
def stop_monitor(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Stop background IMAP polling for the current user."""
    imap_cred = db.query(ImapCredential).filter(ImapCredential.user_id == current_user.id).first()
    if imap_cred:
        imap_cred.is_active = False
        db.commit()

    inbox_monitor.stop_monitoring_user(current_user.id)
    return {
        "success": True,
        "message": "Live monitoring stopped.",
        "running": False,
    }


@router.post("/restart")
def restart_monitor(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Restart background IMAP polling thread for the current user."""
    imap_cred = db.query(ImapCredential).filter(ImapCredential.user_id == current_user.id).first()
    if not imap_cred:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Configure your IMAP credentials first before restarting live monitoring.",
        )

    inbox_monitor.stop_monitoring_user(current_user.id)
    import time
    time.sleep(0.3)
    imap_cred.is_active = True
    db.commit()

    inbox_monitor.start_monitoring_user(current_user.id, process_incoming_email)
    return {
        "success": True,
        "message": "Live monitoring restarted.",
        "running": True,
    }


@router.post("/poll-now")
def poll_now(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Trigger an immediate mailbox poll check."""
    imap_cred = db.query(ImapCredential).filter(ImapCredential.user_id == current_user.id).first()
    if not imap_cred:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Configure your IMAP credentials first before polling.",
        )

    imap_cred.is_active = True
    db.commit()

    inbox_monitor.start_monitoring_user(current_user.id, process_incoming_email)
    inbox_monitor.poll_now(process_incoming_email, user_id=current_user.id)
    return {
        "success": True,
        "message": "Triggered immediate inbox check.",
    }


@router.post("/test-connection")
def test_connection(body: TestConnectionInput, current_user: User = Depends(get_current_user)):
    """Test connecting to the IMAP server with provided credentials."""
    ok, err = inbox_monitor.test_login(
        body.imap_host,
        body.imap_port,
        body.imap_email,
        body.app_password,
    )
    if not ok:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err)
    return {"success": True, "message": "IMAP connection successful!"}


@router.post("/credentials")
def save_credentials(
    body: ImapCredentialInput,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Save IMAP credentials, test connection, and activate monitoring if requested."""
    ok, err = inbox_monitor.test_login(
        body.imap_host,
        body.imap_port,
        body.imap_email,
        body.app_password,
    )
    if not ok:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err)

    enc_pass = database.encrypt_password(body.app_password)
    now = datetime.now(timezone.utc)

    existing = db.query(ImapCredential).filter(ImapCredential.user_id == current_user.id).first()
    if existing:
        existing.imap_host = body.imap_host
        existing.imap_port = body.imap_port
        existing.imap_email = body.imap_email
        existing.encrypted_pass = enc_pass
        existing.is_active = body.is_active
        existing.updated_at = now
    else:
        new_cred = ImapCredential(
            user_id=current_user.id,
            imap_host=body.imap_host,
            imap_port=body.imap_port,
            imap_email=body.imap_email,
            encrypted_pass=enc_pass,
            is_active=body.is_active,
            created_at=now,
            updated_at=now,
        )
        db.add(new_cred)

    db.commit()

    if body.is_active:
        inbox_monitor.start_monitoring_user(current_user.id, process_incoming_email)
    else:
        inbox_monitor.stop_monitoring_user(current_user.id)

    return {
        "success": True,
        "message": "IMAP credentials saved successfully and verified.",
        "is_active": body.is_active,
    }
