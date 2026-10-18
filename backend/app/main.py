"""
backend/app/main.py
-------------------
FastAPI application factory, lifespan management, CORS, rate limiting, and router registration.
"""
import os
import sys
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded

from backend.app.core.config import get_settings
from backend.app.core.limiter import limiter
from backend.app.database.session import engine, Base, SessionLocal
from backend.app.models.user import User
from backend.app.models.model_version import ModelVersion
from backend.app.security.hashing import hash_password
from backend.app.ml.inference import load_model, get_model_status
from backend.app.api import (
    auth,
    scans,
    analysis,
    dashboard,
    admin,
    model_api,
    settings_api,
    monitor_api,
)

logger = logging.getLogger("email_threat_api")
settings = get_settings()


def _seed_admin_and_defaults():
    """Ensure database tables exist and superadmin is seeded if configured."""
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database schema initialized/verified.")
    except Exception as e:
        logger.warning(f"Failed to create_all tables (may already exist or read-only): {e}")

    if not settings.ADMIN_EMAIL or not settings.ADMIN_PASSWORD:
        return

    db = SessionLocal()
    try:
        existing_admin = db.query(User).filter(
            (User.email == settings.ADMIN_EMAIL.lower()) | (User.username == settings.ADMIN_USERNAME)
        ).first()

        if not existing_admin:
            logger.info(f"Seeding superadmin account: {settings.ADMIN_EMAIL}")
            admin_user = User(
                name="Super Administrator",
                username=settings.ADMIN_USERNAME,
                email=settings.ADMIN_EMAIL.lower().strip(),
                password_hash=hash_password(settings.ADMIN_PASSWORD),
                role="admin",
                is_active=True,
            )
            db.add(admin_user)
            db.commit()
            logger.info("Superadmin account successfully seeded.")
        else:
            # Ensure role is admin
            if existing_admin.role != "admin":
                existing_admin.role = "admin"
                db.commit()
    except Exception as e:
        db.rollback()
        logger.warning(f"Admin seeding check failed: {e}")
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting Email Threat Detection API 2.0...")
    _seed_admin_and_defaults()
    try:
        load_model()
        logger.info("ML model pre-loaded successfully.")
    except Exception as e:
        logger.warning(f"ML model failed to pre-load: {e}")

    try:
        from backend.app.api.monitor_api import process_incoming_email
        from modules import inbox_monitor
        inbox_monitor.start_monitoring(process_incoming_email)
        logger.info("Real-time IMAP inbox monitoring initialized.")
    except Exception as e:
        logger.warning(f"Could not auto-start IMAP monitor: {e}")

    yield
    # Shutdown
    logger.info("Shutting down Email Threat Detection API...")
    try:
        from modules import inbox_monitor
        inbox_monitor.stop_monitoring()
    except Exception:
        pass


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="High-performance email threat scoring, spoofing detection, hop geolocation, and forensic intelligence API.",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# SlowAPI Rate Limiter integration
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def custom_rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={
            "detail": "Too many requests. Please slow down and try again shortly.",
            "retry_after": exc.detail if hasattr(exc, "detail") else "60 seconds",
        },
    )


# CORS Configuration
origins = list(set(settings.CORS_ORIGINS + [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]))

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)

# Register Routers
app.include_router(auth.router)
app.include_router(scans.router)
app.include_router(analysis.router)
app.include_router(dashboard.router)
app.include_router(admin.router)
app.include_router(model_api.router)
app.include_router(settings_api.router)
app.include_router(monitor_api.router)


@app.get("/", tags=["General"])
def root():
    return {
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "online",
        "docs_url": "/docs",
        "health_check": "/api/health",
    }


@app.get("/health", tags=["General"])
@app.get("/api/health", tags=["General"])
def health():
    db_status = "connected"
    try:
        with engine.connect() as conn:
            pass
    except Exception as e:
        db_status = f"unhealthy: {e}"

    model_info = get_model_status()

    return {
        "status": "ok" if db_status == "connected" else "degraded",
        "database": db_status,
        "model": model_info,
        "environment": settings.ENVIRONMENT,
        "version": settings.APP_VERSION,
    }
