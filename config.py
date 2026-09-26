"""
config.py
---------
Every tunable number/list used across the project lives here.
If a check feels too strict or too loose during testing, change it here
instead of digging through the module code.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# --- Flask & Security ---
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
WTF_CSRF_ENABLED = True
WTF_CSRF_TIME_LIMIT = 3600  # 1 hour

# --- Super Admin (fixed site-owner credentials) ---
SUPER_ADMIN_EMAIL    = os.getenv("ADMIN_EMAIL",    "admin@emailthreat.com")
SUPER_ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "Admin@1234")
SUPER_ADMIN_USERNAME = "superadmin"

# --- Flask-Mail (password reset) ---
# Reuses the same Gmail App Password already set for IMAP monitoring.
MAIL_SERVER   = os.getenv("MAIL_SERVER",   "smtp.gmail.com")
MAIL_PORT     = int(os.getenv("MAIL_PORT", "587"))
MAIL_USE_TLS  = True
MAIL_USERNAME = os.getenv("MAIL_USERNAME", os.getenv("IMAP_USER", ""))
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", os.getenv("IMAP_PASS", ""))
MAIL_DEFAULT_SENDER = os.getenv("MAIL_USERNAME", os.getenv("IMAP_USER", "noreply@emailthreat.com"))

# --- Password reset token expiry (seconds) ---
PASSWORD_RESET_EXPIRY = 3600  # 1 hour
MAX_UPLOAD_MB = 5
ALLOWED_EXTENSIONS = {".eml", ".txt"}
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "False").lower() in ("true", "1", "yes")

# --- Optional API keys (leave blank in .env to disable) ---
VT_API_KEY = os.getenv("VT_API_KEY", "")

# --- Paths & Database ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
REPORT_DIR = os.path.join(BASE_DIR, "reports")
MODEL_DIR = os.path.join(BASE_DIR, "model")
DB_PATH = os.path.join(BASE_DIR, "scans.db")
DATABASE_URL = os.getenv("DATABASE_URL", "")


# ===================== HEADER ANALYSIS =====================
KNOWN_BRANDS = [
    "paypal", "amazon", "google", "microsoft", "apple", "netflix",
    "sbi", "hdfc", "icici", "facebook", "instagram", "whatsapp", "bank"
]
FREEMAIL_DOMAINS = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "rediffmail.com"]

HEADER_POINTS = {
    "spf_fail": 25,
    "spf_none": 10,
    "dkim_fail": 20,
    "dkim_none": 8,
    "dmarc_fail": 15,
    "reply_to_mismatch": 20,
    "return_path_mismatch": 15,
    "freemail_brand_impersonation": 30,
    "lookalike_domain": 35,
    "missing_message_id": 5,
    "missing_date": 5,
    "suspicious_subject": 15,
}

# ===================== URL ANALYSIS =====================
URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "ow.ly", "buff.ly"]
SUSPICIOUS_TLDS = [".xyz", ".top", ".tk", ".click", ".zip", ".gq", ".ml", ".cf", ".work"]

URL_POINTS = {
    "ip_based_url": 30,
    "long_url": 10,
    "shortener": 15,
    "at_symbol": 25,
    "many_subdomains": 15,
    "not_https": 10,
    "anchor_mismatch": 30,
    "suspicious_tld": 15,
    "punycode": 25,
    "lookalike_domain": 35,
}
LONG_URL_THRESHOLD = 75
MAX_SUBDOMAINS = 3
MAX_VT_URL_LOOKUPS = 4

# ===================== ATTACHMENT ANALYSIS =====================
HIGH_RISK_EXTENSIONS = [".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".jar", ".msi", ".lnk", ".iso", ".hta"]
MACRO_EXTENSIONS = [".docm", ".xlsm", ".pptm"]
ARCHIVE_EXTENSIONS = [".zip", ".rar", ".7z"]

ATTACHMENT_POINTS = {
    "high_risk_extension": 60,
    "macro_enabled": 45,
    "double_extension": 50,
    "archive_unknown_contents": 15,
    "extension_mismatch": 30,
}
MAX_VT_HASH_LOOKUPS = 4

# ===================== GEOLOCATION =====================
MAX_GEO_LOOKUPS = 8
HIGH_RISK_COUNTRIES = []  # left empty on purpose - weak/unfair signal, see README

GEO_POINTS = {
    "proxy_or_hosting_origin": 20,
    "many_countries": 10,
    "no_public_ip": 20,
    "high_risk_country": 10,
}
MAX_COUNTRIES_BEFORE_FLAG = 3

# ===================== SCORING =====================
WEIGHTS = {
    "content": 0.40,
    "header": 0.25,
    "url": 0.25,
    "attachment": 0.10,
}
GEO_BONUS_CAP = 10

VERDICT_THRESHOLDS = {
    "Safe": (0, 30),
    "Suspicious": (31, 65),
    "Dangerous": (66, 100),
}

# ===================== REAL-TIME INBOX MONITORING (IMAP) =====================
# For Gmail: enable IMAP in Gmail settings, then create an "App Password"
# (Google Account -> Security -> App Passwords). Do NOT use your normal password.
IMAP_HOST = os.getenv("IMAP_HOST", "imap.gmail.com")
IMAP_PORT = int(os.getenv("IMAP_PORT", "993"))
IMAP_USER = os.getenv("IMAP_USER", "")
IMAP_PASS = os.getenv("IMAP_PASS", "")
POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "30"))

# ===================== CONTENT / KEYWORDS =====================
SUSPICIOUS_PHRASES = [
    "verify your account", "urgent", "act now", "click here", "suspended",
    "confirm your password", "limited time", "you have won", "wire transfer",
    "update your billing", "unusual activity", "immediate action required",
]
