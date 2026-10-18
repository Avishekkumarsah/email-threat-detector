"""
backend/app/core/config.py
---------------------------
Application configuration using Pydantic BaseSettings.
All values loaded from environment variables / .env file.
"""
from functools import lru_cache
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator
import secrets


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Core ──────────────────────────────────────────────────────────────────
    APP_NAME: str = "AI-Based Phishing & Email Threat Detection System"
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "production"

    # ── Security ──────────────────────────────────────────────────────────────
    SECRET_KEY: str = "7f3e9a1b2c4d5e6f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f"
    JWT_SECRET_KEY: Optional[str] = None
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    @field_validator("JWT_SECRET_KEY", mode="before")
    @classmethod
    def set_jwt_secret(cls, v, info):
        if not v:
            return "7f3e9a1b2c4d5e6f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f"
        return v

    # ── Database ──────────────────────────────────────────────────────────────
    DATABASE_URL: str

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def clean_db_url(cls, v: str) -> str:
        if isinstance(v, str):
            import re
            v = v.strip()
            v = re.sub(r"[&?]channel_binding=[^&]*", "", v)
        return v

    # ── CORS ──────────────────────────────────────────────────────────────────
    CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173", "http://127.0.0.1:3000"]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors(cls, v):
        if isinstance(v, str):
            return [i.strip() for i in v.split(",") if i.strip()]
        return v

    # ── Upload ────────────────────────────────────────────────────────────────
    MAX_UPLOAD_SIZE_MB: int = 10
    ALLOWED_EXTENSIONS: List[str] = [".eml", ".txt"]
    UPLOAD_DIR: str = "uploads"
    REPORT_DIR: str = "reports"

    # ── ML Model ──────────────────────────────────────────────────────────────
    MODEL_PATH: str = "model/phishing_model.pkl"
    VECTORIZER_PATH: str = "model/vectorizer.pkl"
    METRICS_PATH: str = "model/metrics.json"
    MODEL_VERSION: str = "1.0.0"

    # ── Scoring thresholds ────────────────────────────────────────────────────
    SCORE_LOW_RISK_MAX: int = 20
    SCORE_MEDIUM_RISK_MAX: int = 45
    SCORE_HIGH_RISK_MAX: int = 70
    SCORE_CRITICAL_RISK_MAX: int = 100
    SCORING_RULE_VERSION: str = "2.0"

    # ── External APIs ─────────────────────────────────────────────────────────
    URL_REPUTATION_API_KEY: str = ""   # VirusTotal
    MAX_VT_URL_LOOKUPS: int = 4
    MAX_VT_HASH_LOOKUPS: int = 4

    # ── Retention ─────────────────────────────────────────────────────────────
    SCAN_RETENTION_DAYS: int = 90

    # ── Admin ─────────────────────────────────────────────────────────────────
    ADMIN_EMAIL: str = ""
    ADMIN_PASSWORD: str = ""
    ADMIN_USERNAME: str = "superadmin"

    # ── Mail ─────────────────────────────────────────────────────────────────
    MAIL_SERVER: str = "smtp.gmail.com"
    MAIL_PORT: int = 587
    MAIL_USERNAME: str = ""
    MAIL_PASSWORD: str = ""
    MAIL_DEFAULT_SENDER: str = "noreply@emailthreat.com"

    # ── IMAP Monitoring ───────────────────────────────────────────────────────
    POLL_INTERVAL_SECONDS: int = 30

    # ── Rate limiting ─────────────────────────────────────────────────────────
    RATE_LIMIT_LOGIN: str = "5/minute"
    RATE_LIMIT_REGISTER: str = "3/minute"
    RATE_LIMIT_SCAN: str = "20/minute"

    # ── Scoring weights ───────────────────────────────────────────────────────
    WEIGHT_CONTENT: float = 0.40
    WEIGHT_HEADER: float = 0.25
    WEIGHT_URL: float = 0.25
    WEIGHT_ATTACHMENT: float = 0.10
    GEO_BONUS_CAP: int = 10

    # ── Header analysis points ─────────────────────────────────────────────────
    HEADER_POINTS: dict = {
        "spf_fail": 25, "spf_none": 10, "dkim_fail": 20, "dkim_none": 8,
        "dmarc_fail": 15, "reply_to_mismatch": 20, "return_path_mismatch": 15,
        "freemail_brand_impersonation": 30, "lookalike_domain": 35,
        "missing_message_id": 5, "missing_date": 5, "suspicious_subject": 15,
    }

    # ── URL analysis points ────────────────────────────────────────────────────
    URL_POINTS: dict = {
        "ip_based_url": 30, "long_url": 10, "shortener": 15, "at_symbol": 25,
        "many_subdomains": 15, "not_https": 10, "anchor_mismatch": 30,
        "suspicious_tld": 15, "punycode": 25, "lookalike_domain": 35,
    }
    LONG_URL_THRESHOLD: int = 75
    MAX_SUBDOMAINS: int = 3
    URL_SHORTENERS: List[str] = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "ow.ly", "buff.ly"
    ]
    SUSPICIOUS_TLDS: List[str] = [
        ".xyz", ".top", ".tk", ".click", ".zip", ".gq", ".ml", ".cf", ".work"
    ]

    # ── Attachment points ──────────────────────────────────────────────────────
    ATTACHMENT_POINTS: dict = {
        "high_risk_extension": 60, "macro_enabled": 45,
        "double_extension": 50, "archive_unknown_contents": 15, "extension_mismatch": 30,
    }
    HIGH_RISK_EXTENSIONS: List[str] = [
        ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".jar", ".msi", ".lnk", ".iso", ".hta"
    ]
    MACRO_EXTENSIONS: List[str] = [".docm", ".xlsm", ".pptm"]
    ARCHIVE_EXTENSIONS: List[str] = [".zip", ".rar", ".7z"]

    # ── Known brands for impersonation detection ──────────────────────────────
    KNOWN_BRANDS: List[str] = [
        "paypal", "amazon", "google", "microsoft", "apple", "netflix",
        "sbi", "hdfc", "icici", "facebook", "instagram", "whatsapp", "bank"
    ]
    FREEMAIL_DOMAINS: List[str] = [
        "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "rediffmail.com"
    ]

    # ── Suspicious phrases ─────────────────────────────────────────────────────
    SUSPICIOUS_PHRASES: List[str] = [
        "verify your account", "urgent", "act now", "click here", "suspended",
        "confirm your password", "limited time", "you have won", "wire transfer",
        "update your billing", "unusual activity", "immediate action required",
    ]


@lru_cache()
def get_settings() -> Settings:
    return Settings()
