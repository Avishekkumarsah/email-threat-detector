"""
database.py
-----------
Multi-tenant SQLite wrapper.

Tables
------
users            — registered accounts
imap_credentials — per-user IMAP config (password encrypted with Fernet)
scans            — all scan results, tagged with user_id

Encryption
----------
Fernet (AES-128-CBC + HMAC-SHA256) is used to encrypt IMAP passwords at rest.
The key is derived from the app's SECRET_KEY.  If SECRET_KEY changes, stored
passwords cannot be decrypted — keep it stable in production.
"""

import sqlite3
import json
import base64
import hashlib
from datetime import datetime

import config

# ── Fernet key derived from SECRET_KEY ──────────────────────────────────────
def _get_fernet():
    from cryptography.fernet import Fernet
    # Derive a 32-byte key from SECRET_KEY using SHA-256, then base64url-encode it
    raw = hashlib.sha256(config.SECRET_KEY.encode()).digest()
    key = base64.urlsafe_b64encode(raw)
    return Fernet(key)


def encrypt_password(plain_text: str) -> str:
    """Encrypt a plain-text password; returns a url-safe str."""
    f = _get_fernet()
    return f.encrypt(plain_text.encode()).decode()


def decrypt_password(cipher_text: str) -> str:
    """Decrypt a Fernet cipher-text back to plain text."""
    f = _get_fernet()
    return f.decrypt(cipher_text.encode()).decode()


# ── DB connection ─────────────────────────────────────────────────────────────
def _connect():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _column_exists(conn, table: str, column: str) -> bool:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(r["name"] == column for r in rows)


# ── Schema init / migration ──────────────────────────────────────────────────
def init_db():
    conn = _connect()

    # Users table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    NOT NULL UNIQUE,
            email         TEXT    NOT NULL UNIQUE,
            password_hash TEXT    NOT NULL,
            created_at    TEXT    NOT NULL,
            is_admin      INTEGER NOT NULL DEFAULT 0
        )
    """)

    # Migration: add is_admin column to existing users table if absent
    if not _column_exists(conn, "users", "is_admin"):
        conn.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")

    # Migration: add last_login column to existing users table if absent
    if not _column_exists(conn, "users", "last_login"):
        conn.execute("ALTER TABLE users ADD COLUMN last_login TEXT")

    # Ensure at least one admin exists (make user ID 1 admin)
    has_admin = conn.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1").fetchone()[0]
    if not has_admin:
        conn.execute("UPDATE users SET is_admin = 1 WHERE id = (SELECT id FROM users ORDER BY id ASC LIMIT 1)")

    # IMAP credentials table (one row per user)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS imap_credentials (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id        INTEGER NOT NULL UNIQUE,
            imap_host      TEXT    NOT NULL,
            imap_port      INTEGER NOT NULL DEFAULT 993,
            imap_email     TEXT    NOT NULL,
            encrypted_pass TEXT    NOT NULL,
            is_active      INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    # Legacy scans table (create if not exists)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            filename        TEXT,
            scan_date       TEXT,
            file_hash       TEXT,
            sender          TEXT,
            subject         TEXT,
            final_score     INTEGER,
            verdict         TEXT,
            full_result_json TEXT,
            user_id         INTEGER REFERENCES users(id) ON DELETE SET NULL
        )
    """)

    # Password Reset Tokens table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            token      TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            used       INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    # Migration: add user_id column to existing scans table if absent
    if not _column_exists(conn, "scans", "user_id"):
        conn.execute("ALTER TABLE scans ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE SET NULL")

    conn.commit()
    conn.close()


def migrate_existing_scans_to_user(user_id: int):
    """Assign all scans that have no user_id to the given user (first admin)."""
    conn = _connect()
    conn.execute("UPDATE scans SET user_id = ? WHERE user_id IS NULL", (user_id,))
    conn.commit()
    conn.close()


# ── User CRUD ─────────────────────────────────────────────────────────────────
def create_user(username: str, email: str, password_hash: str) -> int:
    conn = _connect()
    try:
        now = datetime.now().isoformat(timespec="seconds")
        cur = conn.execute(
            "INSERT INTO users (username, email, password_hash, created_at, last_login) VALUES (?, ?, ?, ?, ?)",
            (username.strip(), email.strip().lower(), password_hash, now, now),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def get_user_by_id(user_id: int):
    conn = _connect()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_username(username: str):
    if not username:
        return None
    conn = _connect()
    row = conn.execute("SELECT * FROM users WHERE LOWER(username) = LOWER(?)", (username.strip(),)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_email(email: str):
    if not email:
        return None
    conn = _connect()
    row = conn.execute("SELECT * FROM users WHERE LOWER(email) = LOWER(?)", (email.strip(),)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_identifier(identifier: str):
    """Search for user by username OR email case-insensitively."""
    if not identifier:
        return None
    val = identifier.strip()
    conn = _connect()
    row = conn.execute(
        "SELECT * FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)",
        (val, val.lower())
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def update_last_login(user_id: int):
    """Record current timestamp as last_login for the given user_id."""
    conn = _connect()
    conn.execute(
        "UPDATE users SET last_login = ? WHERE id = ?",
        (datetime.now().isoformat(timespec="seconds"), user_id)
    )
    conn.commit()
    conn.close()


def count_users() -> int:
    conn = _connect()
    count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    conn.close()
    return count


def is_super_admin(user_id: int) -> bool:
    """Return True if user_id belongs to the hardcoded super admin account."""
    conn = _connect()
    row = conn.execute("SELECT email FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if not row:
        return False
    return row["email"].lower() == config.SUPER_ADMIN_EMAIL.lower()


def ensure_super_admin():
    """
    Called once at app startup.
    Creates (or repairs) the fixed Super Admin account from config.
    The super admin is ALWAYS is_admin=1 and can never be demoted via the UI.
    """
    from werkzeug.security import generate_password_hash

    email    = config.SUPER_ADMIN_EMAIL.lower().strip()
    username = config.SUPER_ADMIN_USERNAME.strip()
    now      = datetime.now().isoformat(timespec="seconds")

    conn = _connect()
    existing = conn.execute("SELECT id, is_admin FROM users WHERE LOWER(email) = LOWER(?)", (email,)).fetchone()
    if existing:
        # Account exists — ensure is_admin = 1 without overwriting registered password
        conn.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (existing["id"],))
        conn.commit()
    else:
        # Create the super admin for the first time
        pw_hash = generate_password_hash(config.SUPER_ADMIN_PASSWORD)
        conn.execute(
            "INSERT INTO users (username, email, password_hash, created_at, last_login, is_admin) "
            "VALUES (?, ?, ?, ?, ?, 1)",
            (username, email, pw_hash, now, now),
        )
        conn.commit()
    conn.close()


# ── IMAP Credentials CRUD ─────────────────────────────────────────────────────
def save_imap_credentials(user_id: int, host: str, port: int, email: str, plain_password: str, is_active: bool = True):
    encrypted = encrypt_password(plain_password)
    conn = _connect()
    conn.execute("""
        INSERT INTO imap_credentials (user_id, imap_host, imap_port, imap_email, encrypted_pass, is_active)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            imap_host      = excluded.imap_host,
            imap_port      = excluded.imap_port,
            imap_email     = excluded.imap_email,
            encrypted_pass = excluded.encrypted_pass,
            is_active      = excluded.is_active
    """, (user_id, host, port, email, encrypted, 1 if is_active else 0))
    conn.commit()
    conn.close()


def get_imap_credentials(user_id: int):
    """Return the IMAP credential row for a user (password still encrypted)."""
    conn = _connect()
    row = conn.execute(
        "SELECT * FROM imap_credentials WHERE user_id = ?", (user_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def set_imap_active(user_id: int, is_active: bool):
    conn = _connect()
    conn.execute(
        "UPDATE imap_credentials SET is_active = ? WHERE user_id = ?",
        (1 if is_active else 0, user_id),
    )
    conn.commit()
    conn.close()


def get_all_active_imap_credentials():
    """Return all rows where is_active=1 (used by inbox_monitor)."""
    conn = _connect()
    rows = conn.execute(
        "SELECT * FROM imap_credentials WHERE is_active = 1"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Scans CRUD ────────────────────────────────────────────────────────────────
def save_scan(data: dict, user_id: int = None) -> int:
    conn = _connect()
    cur = conn.execute(
        """INSERT INTO scans
           (filename, scan_date, file_hash, sender, subject, final_score, verdict, full_result_json, user_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            data.get("filename"),
            datetime.now().isoformat(timespec="seconds"),
            data.get("file_hash"),
            data.get("sender"),
            data.get("subject"),
            data.get("final_score"),
            data.get("verdict"),
            json.dumps(data.get("full_result", {})),
            user_id,
        ),
    )
    conn.commit()
    new_id = cur.lastrowid
    conn.close()
    return new_id


def get_all_scans(user_id: int = None):
    conn = _connect()
    if user_id is not None:
        rows = conn.execute(
            "SELECT id, filename, scan_date, sender, subject, final_score, verdict "
            "FROM scans WHERE user_id = ? ORDER BY id DESC",
            (user_id,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, filename, scan_date, sender, subject, final_score, verdict "
            "FROM scans ORDER BY id DESC"
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_scan_by_id(scan_id: int):
    conn = _connect()
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    if not row:
        return None
    result = dict(row)
    try:
        result["full_result"] = json.loads(result.pop("full_result_json"))
    except Exception:
        result["full_result"] = {}
    return result


def delete_scan(scan_id: int):
    conn = _connect()
    conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()
    return True


# ── Admin Dashboard Helpers ───────────────────────────────────────────────────
def get_all_users_with_stats():
    """Returns detailed user records along with scan counts and active IMAP status for admin."""
    conn = _connect()
    rows = conn.execute("""
        SELECT u.id, u.username, u.email, u.created_at, u.last_login, u.is_admin,
               (SELECT COUNT(*) FROM scans s WHERE s.user_id = u.id) AS scan_count,
               ic.is_active AS imap_active,
               ic.imap_email
        FROM users u
        LEFT JOIN imap_credentials ic ON ic.user_id = u.id
        ORDER BY u.id ASC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_admin_dashboard_stats():
    """Aggregates system-wide analytics for the admin panel."""
    conn = _connect()
    total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    total_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    active_monitors = conn.execute("SELECT COUNT(*) FROM imap_credentials WHERE is_active = 1").fetchone()[0]

    verdict_rows = conn.execute("SELECT verdict, COUNT(*) as cnt FROM scans GROUP BY verdict").fetchall()
    verdicts = {r["verdict"]: r["cnt"] for r in verdict_rows}

    conn.close()
    return {
        "total_users": total_users,
        "total_scans": total_scans,
        "active_monitors": active_monitors,
        "safe_scans": verdicts.get("Safe", 0),
        "suspicious_scans": verdicts.get("Suspicious", 0),
        "dangerous_scans": verdicts.get("Dangerous", 0),
    }


def update_user_password(user_id: int, password_hash: str) -> bool:
    """Update password hash for a user."""
    conn = _connect()
    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
    conn.commit()
    conn.close()
    return True


def create_password_reset_token(user_id: int, token: str, expires_at_iso: str):
    """Save a password reset token for a user."""
    conn = _connect()
    conn.execute(
        "INSERT INTO password_reset_tokens (user_id, token, expires_at, used) VALUES (?, ?, ?, 0)",
        (user_id, token, expires_at_iso)
    )
    conn.commit()
    conn.close()


def verify_password_reset_token(token: str):
    """
    Check if a reset token is valid, unused, and not expired.
    Returns (user_id, error_message).
    """
    conn = _connect()
    row = conn.execute(
        "SELECT user_id, expires_at, used FROM password_reset_tokens WHERE token = ?",
        (token,)
    ).fetchone()
    conn.close()

    if not row:
        return None, "Invalid or expired password reset link."
    if row["used"]:
        return None, "This reset link has already been used."

    exp = datetime.fromisoformat(row["expires_at"])
    if datetime.now() > exp:
        return None, "This reset link has expired. Please request a new one."

    return row["user_id"], None


def consume_password_reset_token(token: str):
    """Mark a reset token as used."""
    conn = _connect()
    conn.execute("UPDATE password_reset_tokens SET used = 1 WHERE token = ?", (token,))
    conn.commit()
    conn.close()


def get_user_analytics(user_id: int = None):
    """
    Calculates detailed analytics data for the dashboard charts:
    - Verdict counts (Safe, Suspicious, Dangerous)
    - Average threat score
    - Recent scans timeseries (last 7 days / recent dates)
    """
    conn = _connect()
    where_clause = "WHERE user_id = ?" if user_id is not None else ""
    params = (user_id,) if user_id is not None else ()

    # Total & Verdict counts
    rows = conn.execute(f"SELECT verdict, final_score, scan_date FROM scans {where_clause} ORDER BY id ASC", params).fetchall()
    conn.close()

    total = len(rows)
    safe_cnt = sum(1 for r in rows if r["verdict"] == "Safe")
    susp_cnt = sum(1 for r in rows if r["verdict"] == "Suspicious")
    dang_cnt = sum(1 for r in rows if r["verdict"] == "Dangerous")
    avg_score = round(sum(r["final_score"] for r in rows) / total, 1) if total > 0 else 0

    # Group scans by date (YYYY-MM-DD) for line/bar chart
    date_map = {}
    for r in rows:
        d_str = (r["scan_date"] or "")[:10]
        if not d_str:
            continue
        if d_str not in date_map:
            date_map[d_str] = {"safe": 0, "suspicious": 0, "dangerous": 0, "total": 0}
        date_map[d_str]["total"] += 1
        v_key = (r["verdict"] or "Safe").lower()
        if v_key in date_map[d_str]:
            date_map[d_str][v_key] += 1

    # Take latest 10 dates
    sorted_dates = sorted(date_map.keys())[-10:]
    chart_dates = sorted_dates
    chart_safe = [date_map[d]["safe"] for d in sorted_dates]
    chart_suspicious = [date_map[d]["suspicious"] for d in sorted_dates]
    chart_dangerous = [date_map[d]["dangerous"] for d in sorted_dates]

    return {
        "total_scans": total,
        "avg_score": avg_score,
        "verdict_counts": {
            "Safe": safe_cnt,
            "Suspicious": susp_cnt,
            "Dangerous": dang_cnt,
        },
        "timeseries": {
            "dates": chart_dates,
            "safe": chart_safe,
            "suspicious": chart_suspicious,
            "dangerous": chart_dangerous,
        }
    }


def toggle_user_admin(user_id: int):
    """Toggle is_admin status for a user."""
    conn = _connect()
    user = conn.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
    if user:
        new_status = 0 if user["is_admin"] else 1
        conn.execute("UPDATE users SET is_admin = ? WHERE id = ?", (new_status, user_id))
        conn.commit()
    conn.close()
    return True
