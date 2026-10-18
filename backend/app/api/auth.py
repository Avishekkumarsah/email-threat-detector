"""
backend/app/api/auth.py
------------------------
Authentication endpoints: register, login, refresh, logout, me.
"""
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.models.user import User
from backend.app.models.password_reset import PasswordResetToken
from backend.app.schemas.auth import (
    RegisterRequest, LoginRequest, TokenResponse, RefreshRequest,
    UserResponse, ForgotPasswordRequest, ResetPasswordRequest, PasswordChangeRequest
)
from backend.app.security.hashing import hash_password, verify_password
from backend.app.security.jwt import (
    create_access_token, create_refresh_token, decode_token
)
from backend.app.security.dependencies import get_current_user
from backend.app.services.audit_service import log_event
from backend.app.core.limiter import limiter
from backend.app.core.config import get_settings

import secrets

settings = get_settings()
router = APIRouter(prefix="/api/auth", tags=["Authentication"])


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    return forwarded.split(",")[0].strip() if forwarded else request.client.host


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(settings.RATE_LIMIT_REGISTER)
def register(request: Request, body: RegisterRequest, db: Session = Depends(get_db)):
    """Register a new user account."""
    # Check duplicates
    if db.query(User).filter(User.email == body.email.lower()).first():
        raise HTTPException(status_code=409, detail="An account with that email already exists.")
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(status_code=409, detail="Username is already taken.")

    user = User(
        name=body.name.strip(),
        username=body.username.strip(),
        email=body.email.lower().strip(),
        password_hash=hash_password(body.password),
        role="user",
        is_active=True,
        last_login=datetime.now(timezone.utc),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    log_event(db, "user.register", actor_user_id=user.id,
              resource_type="user", resource_id=user.id,
              ip_address=_get_client_ip(request))

    access_token = create_access_token({"sub": str(user.id), "role": user.role})
    refresh_token = create_refresh_token({"sub": str(user.id)})
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/login", response_model=TokenResponse)
@limiter.limit(settings.RATE_LIMIT_LOGIN)
def login(request: Request, body: LoginRequest, db: Session = Depends(get_db)):
    """Login with username or email + password. Returns JWT tokens."""
    identifier = body.username_or_email.strip().lower()
    user = (
        db.query(User).filter(User.email == identifier).first()
        or db.query(User).filter(User.username == body.username_or_email.strip()).first()
    )

    if not user or not verify_password(body.password, user.password_hash):
        log_event(db, "user.login.failed", ip_address=_get_client_ip(request),
                  metadata={"identifier": identifier})
        raise HTTPException(status_code=401, detail="Invalid username/email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account suspended. Contact administrator.")

    # Update last login
    user.last_login = datetime.now(timezone.utc)
    db.commit()

    log_event(db, "user.login", actor_user_id=user.id,
              resource_type="user", resource_id=user.id,
              ip_address=_get_client_ip(request))

    access_token = create_access_token({"sub": str(user.id), "role": user.role})
    refresh_token = create_refresh_token({"sub": str(user.id)})
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(body: RefreshRequest, db: Session = Depends(get_db)):
    """Exchange a refresh token for a new access token."""
    payload = decode_token(body.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type.")
    user_id = payload.get("sub")
    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive.")
    access_token = create_access_token({"sub": str(user.id), "role": user.role})
    new_refresh = create_refresh_token({"sub": str(user.id)})
    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Logout — client should discard tokens. Server-side audit log."""
    log_event(db, "user.logout", actor_user_id=current_user.id,
              ip_address=_get_client_ip(request))


@router.get("/me", response_model=UserResponse)
def me(current_user: User = Depends(get_current_user)):
    """Return current authenticated user profile."""
    return current_user


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    body: PasswordChangeRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(body.current_password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect.")
    current_user.password_hash = hash_password(body.new_password)
    db.commit()
    log_event(db, "user.password_change", actor_user_id=current_user.id,
              ip_address=_get_client_ip(request))


@router.post("/forgot-password", status_code=status.HTTP_202_ACCEPTED)
def forgot_password(body: ForgotPasswordRequest, db: Session = Depends(get_db)):
    """Send password reset email. Always returns 202 to prevent email enumeration."""
    user = db.query(User).filter(User.email == body.email.lower()).first()
    if user:
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        prt = PasswordResetToken(user_id=user.id, token=token, expires_at=expires_at)
        db.add(prt)
        db.commit()
        # Email sending would happen here — omitted if MAIL_USERNAME not set
    return {"message": "If an account exists for that email, reset instructions have been sent."}


@router.post("/reset-password", status_code=status.HTTP_204_NO_CONTENT)
def reset_password(body: ResetPasswordRequest, db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    prt = db.query(PasswordResetToken).filter(
        PasswordResetToken.token == body.token,
        PasswordResetToken.used == False,
        PasswordResetToken.expires_at > now,
    ).first()
    if not prt:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token.")
    user = db.query(User).filter(User.id == prt.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    user.password_hash = hash_password(body.new_password)
    prt.used = True
    db.commit()
