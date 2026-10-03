"""
database.py
-----------
Multi-tenant database wrapper.

Supports two backends, auto-selected at startup:
  - PostgreSQL  →  when DATABASE_URL is set in .env  (production)
  - SQLite      →  fallback for local development (no setup required)

All public functions have identical signatures regardless of backend.
Callers (app.py, auth.py, inbox_monitor.py) need zero changes.

Tables
------
users               — registered accounts
imap_credentials    — per-user IMAP config (password encrypted with Fernet)
scans               — all scan results, tagged with user_id
password_reset_tokens — short-lived tokens for password reset flow

Encryption
----------
Fernet (AES-128-CBC + HMAC-SHA256) is used to encrypt IMAP passwords at rest.
The key is derived from the app's SECRET_KEY.  If SECRET_KEY changes, stored
passwords cannot be decrypted — keep it stable in production.
"""

import json
import base64
import hashlib
import traceback
from datetime import datetime

import config

# ── Determine backend ─────────────────────────────────────────────────────────
USE_POSTGRES = bool(config.DATABASE_URL)

# ── Fernet key derived from SECRET_KEY ──────────────────────────────────────
def _get_fernet():
    from cryptography.fernet import Fernet
    raw = hashlib.sha256(config.SECRET_KEY.encode()).digest()
    key = base64.urlsafe_b64encode(raw)
    return Fernet(key)


def encrypt_password(plain_text: str) -> str:
    """Encrypt a plain-text password; returns a url-safe str."""
    return _get_fernet().encrypt(plain_text.encode()).decode()


def decrypt_password(cipher_text: str) -> str:
    """Decrypt a Fernet cipher-text back to plain text."""
    return _get_fernet().decrypt(cipher_text.encode()).decode()


# ── Connection helpers ────────────────────────────────────────────────────────

def _connect_postgres():
    """Return a psycopg2 connection using DATABASE_URL."""
    import psycopg2
    import psycopg2.extras
    conn = psycopg2.connect(config.DATABASE_URL)
    conn.autocommit = False
    return conn


def _connect_sqlite():
    """Return a sqlite3 connection using DB_PATH."""
    import sqlite3
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _connect():
    """Return a connection to the active backend."""
    if USE_POSTGRES:
        return _connect_postgres()
    return _connect_sqlite()


def _cursor(conn):
    """Return a dict-like cursor for the active backend."""
    if USE_POSTGRES:
        import psycopg2.extras
        return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    # sqlite3 already uses Row factory set in _connect_sqlite
    return conn.cursor()


def _ph():
    """Return the correct placeholder for the active backend (%s or ?)."""
    return "%s" if USE_POSTGRES else "?"


def _fetchrow(cur) -> dict | None:
    """Fetch one row as a plain dict."""
    row = cur.fetchone()
    if row is None:
        return None
    return dict(row)


def _fetchall(cur) -> list[dict]:
    """Fetch all rows as plain dicts."""
    return [dict(r) for r in cur.fetchall()]


def _close(conn):
    """Commit and close the connection."""
    try:
        conn.commit()
    except Exception:
        pass
    try:
        conn.close()
    except Exception:
        pass


def _rollback_close(conn):
    """Rollback and close the connection on error."""
    try:
        conn.rollback()
    except Exception:
        pass
    try:
        conn.close()
    except Exception:
        pass


# ── Schema helpers ────────────────────────────────────────────────────────────

def _column_exists_sqlite(conn, table: str, column: str) -> bool:
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    return any(r[1] == column for r in cur.fetchall())


def _column_exists_postgres(conn, table: str, column: str) -> bool:
    cur = _cursor(conn)
    cur.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_name = %s AND column_name = %s",
        (table, column),
    )
    return cur.fetchone() is not None


def _column_exists(conn, table: str, column: str) -> bool:
    if USE_POSTGRES:
        return _column_exists_postgres(conn, table, column)
    return _column_exists_sqlite(conn, table, column)


def _table_exists_postgres(conn, table: str) -> bool:
    cur = _cursor(conn)
    cur.execute(
        "SELECT table_name FROM information_schema.tables "
        "WHERE table_schema='public' AND table_name=%s",
        (table,),
    )
    return cur.fetchone() is not None


# ── Schema init / migration ──────────────────────────────────────────────────

def _init_postgres(conn):
    """Create/migrate schema for PostgreSQL."""
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            SERIAL PRIMARY KEY,
            username      TEXT    NOT NULL UNIQUE,
            email         TEXT    NOT NULL UNIQUE,
            password_hash TEXT    NOT NULL,
            created_at    TEXT    NOT NULL,
            is_admin      INTEGER NOT NULL DEFAULT 0,
            last_login    TEXT,
            is_active     INTEGER NOT NULL DEFAULT 1
        )
    """)

    # Migrations for existing tables
    for col, definition in [
        ("is_admin",  "INTEGER NOT NULL DEFAULT 0"),
        ("last_login","TEXT"),
        ("is_active", "INTEGER NOT NULL DEFAULT 1"),
    ]:
        if not _column_exists_postgres(conn, "users", col):
            cur.execute(f"ALTER TABLE users ADD COLUMN {col} {definition}")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS imap_credentials (
            id             SERIAL PRIMARY KEY,
            user_id        INTEGER NOT NULL UNIQUE,
            imap_host      TEXT    NOT NULL,
            imap_port      INTEGER NOT NULL DEFAULT 993,
            imap_email     TEXT    NOT NULL,
            encrypted_pass TEXT    NOT NULL,
            is_active      INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id               SERIAL PRIMARY KEY,
            filename         TEXT,
            scan_date        TEXT,
            file_hash        TEXT,
            sender           TEXT,
            subject          TEXT,
            final_score      INTEGER,
            verdict          TEXT,
            full_result_json TEXT,
            user_id          INTEGER REFERENCES users(id) ON DELETE SET NULL
        )
    """)

    if not _column_exists_postgres(conn, "scans", "user_id"):
        cur.execute("ALTER TABLE scans ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE SET NULL")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id         SERIAL PRIMARY KEY,
            user_id    INTEGER NOT NULL,
            token      TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            used       INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    conn.commit()


def _init_sqlite(conn):
    """Create/migrate schema for SQLite."""
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

    for col, definition in [
        ("is_admin",  "INTEGER NOT NULL DEFAULT 0"),
        ("last_login","TEXT"),
        ("is_active", "INTEGER NOT NULL DEFAULT 1"),
    ]:
        if not _column_exists_sqlite(conn, "users", col):
            conn.execute(f"ALTER TABLE users ADD COLUMN {col} {definition}")

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

    if not _column_exists_sqlite(conn, "scans", "user_id"):
        conn.execute("ALTER TABLE scans ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE SET NULL")

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

    conn.commit()


def init_db():
    """Initialise or migrate the database schema."""
    conn = _connect()
    try:
        if USE_POSTGRES:
            _init_postgres(conn)
        else:
            _init_sqlite(conn)

        # Ensure at least one admin exists
        ph = _ph()
        cur = _cursor(conn)
        cur.execute("SELECT COUNT(*) as cnt FROM users WHERE is_admin = 1")
        row = _fetchrow(cur)
        if row and (row.get("cnt") or row.get("count(*)") or 0) == 0:
            cur.execute("UPDATE users SET is_admin = 1 WHERE id = (SELECT id FROM users ORDER BY id ASC LIMIT 1)")
        conn.commit()
    finally:
        _close(conn)


def migrate_existing_scans_to_user(user_id: int):
    """Assign all scans that have no user_id to the given user (first admin)."""
    ph = _ph()
    conn = _connect()
    try:
        cur = _cursor(conn)
        cur.execute(f"UPDATE scans SET user_id = {ph} WHERE user_id IS NULL", (user_id,))
        conn.commit()
    finally:
        _close(conn)


# ── User CRUD ─────────────────────────────────────────────────────────────────

def create_user(username: str, email: str, password_hash: str) -> int:
    ph = _ph()
    conn = _connect()
    try:
        now = datetime.now().isoformat(timespec="seconds")
        cur = _cursor(conn)
        if USE_POSTGRES:
            cur.execute(
                f"INSERT INTO users (username, email, password_hash, created_at, last_login, is_active) "
                f"VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, 1) RETURNING id",
                (username.strip(), email.strip().lower(), password_hash, now, now),
            )
            row = _fetchrow(cur)
            new_id = row["id"]
        else:
            cur.execute(
                f"INSERT INTO users (username, email, password_hash, created_at, last_login, is_active) "
                f"VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, 1)",
                (username.strip(), email.strip().lower(), password_hash, now, now),
            )
            new_id = cur.lastrowid
        conn.commit()
        return new_id
    finally:
        _close(conn)


def get_user_by_id(user_id: int) -> dict | None:
    ph = _ph()
    conn = _connect()
    try:
        cur = _cursor(conn)
        cur.execute(f"SELECT * FROM users WHERE id = {ph}", (user_id,))
        return _fetchrow(cur)
    finally:
        _close(conn)


def get_user_by_username(username: str) -> dict | None:
    if not username:
        return None
    ph = _ph()
    conn = _connect()
    try:
        cur = _cursor(conn)
        cur.execute(f"SELECT * FROM users WHERE LOWER(username) = LOWER({ph})", (username.strip(),))
        return _fetchrow(cur)
    finally:
        _close(conn)


def get_user_by_email(email: str) -> dict | None:
    if not email:
        return None
    ph = _ph()
    conn = _connect()
    try:
        cur = _cursor(conn)
        cur.execute(f"SELECT * FROM users WHERE LOWER(email) = LOWER({ph})", (email.strip(),))
        return _fetchrow(cur)
    finally:
        _close(conn)


def get_user_by_identifier(identifier: str) -> dict | None:
    """Search by username OR email, case-insensitively."""
    if not identifier:
        return None
    ph = _ph()
    val = identifier.strip()
    conn = _connect()
    try:
        cur = _cursor(conn)
        cur.execute(
            f"SELECT * FROM users WHERE LOWER(username) = LOWER({ph}) OR LOWER(email) = LOWER({ph})",
            (val, val.lower()),
        )
        return _fetchrow(cur)
    finally:
        _close(conn)


def update_last_login(user_id: int):
    ph = _ph()
    conn = _connect()
    try:
        cur = _cursor(conn)
        cur.execute(
            f"UPDATE users SET last_login = {ph} WHERE id = {ph}",
            (datetime.now().isoformat(timespec="seconds"), user_id),
        )
        conn.commit()
    finally:
        _close(conn)


def count_users() -> int:
    conn = _connect()
    try:
        cur = _cursor(conn)
        cur.execute("SELECT COUNT(*) as cnt FROM users")
        row = _fetchrow(cur)
        return row.get("cnt") or row.get("count(*)") or 0
    finally:
        _close(conn)


def is_super_admin(user_id: int) -> bool:
    ph = _ph()
    conn = _connect()
    try:
        cur = _cursor(conn)
        cur.execute(f"SELECT email FROM users WHERE id = {ph}", (user_id,))
        row = _fetchrow(cur)
        if not row:
            return False
        return row["email"].lower() == config.SUPER_ADMIN_EMAIL.lower()
    finally:
        _close(conn)


def ensure_super_admin():
    """
    Create or repair the fixed Super Admin account from config.
    Called once at app startup.
    """
    from werkzeug.security import generate_password_hash
    ph = _ph()
    email    = config.SUPER_ADMIN_EMAIL.lower().strip()
    username = config.SUPER_ADMIN_USERNAME.strip()
    now      = datetime.now().isoformat(timespec="seconds")

    conn = _connect()
    try:
        cur = _cursor(conn)
        cur.execute(f"SELECT id, is_admin FROM users WHERE LOWER(email) = LOWER({ph})", (email,))
        existing = _fetchrow(cur)
        if existing:
            cur.execute(f"UPDATE users SET is_admin = 1, is_active = 1 WHERE id = {ph}", (existing["id"],))
        else:
            pw_hash = generate_password_hash(config.SUPER_ADMIN_PASSWORD)
            if USE_POSTGRES:
                cur.execute(
                    f"INSERT INTO users (username, email, password_hash, created_at, last_login, is_admin, is_active) "
                    f"VALUES ({ph},{ph},{ph},{ph},{ph},1,1)",
                    (username, email, pw_hash, now, now),
                )
            else:
                cur.execute(
                    f"INSERT INTO users (username, email, password_hash, created_at, last_login, is_admin, is_active) "
                    f"VALUES ({ph},{ph},{ph},{ph},{ph},1,1)",
                    (username, email, pw_hash, now, now),
                )
        conn.commit()
    finally:
        _close(conn)


# ── User status management (admin actions) ────────────────────────────────────

def suspend_user(user_id: int):
    """Suspend (deactivate) a user account."""
    ph = _ph()
    conn = _connect()
    try:
        cur = _cursor(conn)
        cur.execute(f"UPDATE users SET is_active = 0 WHERE id = {ph}", (user_id,))
        conn.commit()
    finally:
        _close(conn)


def activate_user(user_id: int):
    """Re-activate a suspended user account."""
    ph = _ph()
    conn = _connect()
    try:
        cur = _cursor(conn)
        cur.execute(f"UPDATE users SET is_active = 1 WHERE id = {ph}", (user_id,))
        conn.commit()
    finally:
        _close(conn)


def delete_user(user_id: int):
    """
    Permanently delete a user account and cascade-delete their scans
    and IMAP credentials.
    """
    ph = _ph()
    conn = _connect()
    try:
        cur = _cursor(conn)
        # Cascade in code for SQLite safety (foreign keys may not cascade perfectly in old DBs)
        cur.execute(f"DELETE FROM password_reset_tokens WHERE user_id = {ph}", (user_id,))
        cur.execute(f"DELETE FROM imap_credentials WHERE user_id = {ph}", (user_id,))
        cur.execute(f"UPDATE scans SET user_id = NULL WHERE user_id = {ph}", (user_id,))
        cur.execute(f"DELETE FROM users WHERE id = {ph}", (user_id,))
        conn.commit()
    finally:
        _close(conn)


def toggle_user_admin(user_id: int):
    """Toggle is_admin status for a user."""
    ph = _ph()
    conn = _connect()
    try:
        cur = _cursor(conn)
        cur.execute(f"SELECT is_admin FROM users WHERE id = {ph}", (user_id,))
        user = _fetchrow(cur)
        if user:
            new_status = 0 if user["is_admin"] else 1
            cur.execute(f"UPDATE users SET is_admin = {ph} WHERE id = {ph}", (new_status, user_id))
            conn.commit()
    finally:
        _close(conn)
    return True


# ── IMAP Credentials CRUD ─────────────────────────────────────────────────────

def save_imap_credentials(user_id: int, host: str, port: int, email: str,
                           plain_password: str, is_active: bool = True):
    encrypted = encrypt_password(plain_password)
    ph = _ph()
    conn = _connect()
    try:
        cur = _cursor(conn)
        if USE_POSTGRES:
            cur.execute(f"""
                INSERT INTO imap_credentials (user_id, imap_host, imap_port, imap_email, encrypted_pass, is_active)
                VALUES ({ph},{ph},{ph},{ph},{ph},{ph})
                ON CONFLICT(user_id) DO UPDATE SET
                    imap_host      = EXCLUDED.imap_host,
                    imap_port      = EXCLUDED.imap_port,
                    imap_email     = EXCLUDED.imap_email,
                    encrypted_pass = EXCLUDED.encrypted_pass,
                    is_active      = EXCLUDED.is_active
            """, (user_id, host, port, email, encrypted, 1 if is_active else 0))
        else:
            cur.execute(f"""
                INSERT INTO imap_credentials (user_id, imap_host, imap_port, imap_email, encrypted_pass, is_active)
                VALUES ({ph},{ph},{ph},{ph},{ph},{ph})
                ON CONFLICT(user_id) DO UPDATE SET
                    imap_host      = excluded.imap_host,
                    imap_port      = excluded.imap_port,
                    imap_email     = excluded.imap_email,
                    encrypted_pass = excluded.encrypted_pass,
                    is_active      = excluded.is_active
            """, (user_id, host, port, email, encrypted, 1 if is_active else 0))
        conn.commit()
    finally:
        _close(conn)


def get_imap_credentials(user_id: int) -> dict | None:
    ph = _ph()
    conn = _connect()
    try:
        cur = _cursor(conn)
        cur.execute(f"SELECT * FROM imap_credentials WHERE user_id = {ph}", (user_id,))
        return _fetchrow(cur)
    finally:
        _close(conn)


def set_imap_active(user_id: int, is_active: bool):
    ph = _ph()
    conn = _connect()
    try:
        cur = _cursor(conn)
        cur.execute(
            f"UPDATE imap_credentials SET is_active = {ph} WHERE user_id = {ph}",
            (1 if is_active else 0, user_id),
        )
        conn.commit()
    finally:
        _close(conn)


def get_all_active_imap_credentials() -> list[dict]:
    """Return all rows where is_active=1 (used by inbox_monitor)."""
    conn = _connect()
    try:
        cur = _cursor(conn)
        cur.execute("SELECT * FROM imap_credentials WHERE is_active = 1")
        return _fetchall(cur)
    finally:
        _close(conn)


# ── Scans CRUD ────────────────────────────────────────────────────────────────

def save_scan(data: dict, user_id: int = None) -> int:
    ph = _ph()
    conn = _connect()
    try:
        cur = _cursor(conn)
        now = datetime.now().isoformat(timespec="seconds")
        if USE_POSTGRES:
            cur.execute(
                f"INSERT INTO scans (filename, scan_date, file_hash, sender, subject, "
                f"final_score, verdict, full_result_json, user_id) "
                f"VALUES ({ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph}) RETURNING id",
                (
                    data.get("filename"), now, data.get("file_hash"),
                    data.get("sender"), data.get("subject"),
                    data.get("final_score"), data.get("verdict"),
                    json.dumps(data.get("full_result", {})), user_id,
                ),
            )
            row = _fetchrow(cur)
            new_id = row["id"]
        else:
            cur.execute(
                f"INSERT INTO scans (filename, scan_date, file_hash, sender, subject, "
                f"final_score, verdict, full_result_json, user_id) "
                f"VALUES ({ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph})",
                (
                    data.get("filename"), now, data.get("file_hash"),
                    data.get("sender"), data.get("subject"),
                    data.get("final_score"), data.get("verdict"),
                    json.dumps(data.get("full_result", {})), user_id,
                ),
            )
            new_id = cur.lastrowid
        conn.commit()
        return new_id
    finally:
        _close(conn)


def get_all_scans(user_id: int = None) -> list[dict]:
    ph = _ph()
    conn = _connect()
    try:
        cur = _cursor(conn)
        if user_id is not None:
            cur.execute(
                f"SELECT id, filename, scan_date, sender, subject, final_score, verdict "
                f"FROM scans WHERE user_id = {ph} ORDER BY id DESC",
                (user_id,),
            )
        else:
            cur.execute(
                "SELECT id, filename, scan_date, sender, subject, final_score, verdict "
                "FROM scans ORDER BY id DESC"
            )
        return _fetchall(cur)
    finally:
        _close(conn)


def get_scan_by_id(scan_id: int) -> dict | None:
    ph = _ph()
    conn = _connect()
    try:
        cur = _cursor(conn)
        cur.execute(f"SELECT * FROM scans WHERE id = {ph}", (scan_id,))
        row = _fetchrow(cur)
        if not row:
            return None
        try:
            row["full_result"] = json.loads(row.pop("full_result_json"))
        except Exception:
            row["full_result"] = {}
        return row
    finally:
        _close(conn)


def delete_scan(scan_id: int):
    ph = _ph()
    conn = _connect()
    try:
        cur = _cursor(conn)
        cur.execute(f"DELETE FROM scans WHERE id = {ph}", (scan_id,))
        conn.commit()
    finally:
        _close(conn)
    return True


# ── Admin Dashboard Helpers ───────────────────────────────────────────────────

def get_all_users_with_stats() -> list[dict]:
    conn = _connect()
    try:
        cur = _cursor(conn)
        cur.execute("""
            SELECT u.id, u.username, u.email, u.created_at, u.last_login,
                   u.is_admin, u.is_active,
                   (SELECT COUNT(*) FROM scans s WHERE s.user_id = u.id) AS scan_count,
                   ic.is_active AS imap_active,
                   ic.imap_email
            FROM users u
            LEFT JOIN imap_credentials ic ON ic.user_id = u.id
            ORDER BY u.id ASC
        """)
        return _fetchall(cur)
    finally:
        _close(conn)


def get_admin_dashboard_stats() -> dict:
    conn = _connect()
    try:
        cur = _cursor(conn)
        # Total registered users (all-time, including suspended)
        cur.execute("SELECT COUNT(*) as cnt FROM users")
        total_users = (_fetchrow(cur) or {}).get("cnt", 0)

        # Currently active (non-suspended) users
        cur.execute("SELECT COUNT(*) as cnt FROM users WHERE is_active = 1")
        active_users = (_fetchrow(cur) or {}).get("cnt", 0)

        # Suspended users
        cur.execute("SELECT COUNT(*) as cnt FROM users WHERE is_active = 0")
        suspended_users = (_fetchrow(cur) or {}).get("cnt", 0)

        cur.execute("SELECT COUNT(*) as cnt FROM scans")
        total_scans = (_fetchrow(cur) or {}).get("cnt", 0)

        cur.execute("SELECT COUNT(*) as cnt FROM imap_credentials WHERE is_active = 1")
        active_monitors = (_fetchrow(cur) or {}).get("cnt", 0)

        cur.execute("SELECT verdict, COUNT(*) as cnt FROM scans GROUP BY verdict")
        verdicts = {r["verdict"]: r["cnt"] for r in _fetchall(cur)}

        return {
            "total_users":      total_users,     # ALL registered (active + suspended)
            "active_users":     active_users,    # Only non-suspended accounts
            "suspended_users":  suspended_users, # Suspended accounts
            "total_scans":      total_scans,
            "active_monitors":  active_monitors,
            "safe_scans":       verdicts.get("Safe", 0),
            "suspicious_scans": verdicts.get("Suspicious", 0),
            "dangerous_scans":  verdicts.get("Dangerous", 0),
        }
    finally:
        _close(conn)


# ── Analytics ────────────────────────────────────────────────────────────────

def get_user_analytics(user_id: int = None) -> dict:
    ph = _ph()
    conn = _connect()
    try:
        cur = _cursor(conn)
        if user_id is not None:
            cur.execute(
                f"SELECT verdict, final_score, scan_date FROM scans WHERE user_id = {ph} ORDER BY id ASC",
                (user_id,),
            )
        else:
            cur.execute("SELECT verdict, final_score, scan_date FROM scans ORDER BY id ASC")
        rows = _fetchall(cur)
    finally:
        _close(conn)

    total    = len(rows)
    safe_cnt = sum(1 for r in rows if r["verdict"] == "Safe")
    susp_cnt = sum(1 for r in rows if r["verdict"] == "Suspicious")
    dang_cnt = sum(1 for r in rows if r["verdict"] == "Dangerous")
    avg_score = round(sum(r["final_score"] for r in rows) / total, 1) if total > 0 else 0

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

    sorted_dates = sorted(date_map.keys())[-10:]
    return {
        "total_scans": total,
        "avg_score":   avg_score,
        "verdict_counts": {
            "Safe":       safe_cnt,
            "Suspicious": susp_cnt,
            "Dangerous":  dang_cnt,
        },
        "timeseries": {
            "dates":      sorted_dates,
            "safe":       [date_map[d]["safe"]       for d in sorted_dates],
            "suspicious": [date_map[d]["suspicious"] for d in sorted_dates],
            "dangerous":  [date_map[d]["dangerous"]  for d in sorted_dates],
        },
    }


# ── Password Reset ────────────────────────────────────────────────────────────

def update_user_password(user_id: int, password_hash: str) -> bool:
    ph = _ph()
    conn = _connect()
    try:
        cur = _cursor(conn)
        cur.execute(f"UPDATE users SET password_hash = {ph} WHERE id = {ph}", (password_hash, user_id))
        conn.commit()
    finally:
        _close(conn)
    return True


def create_password_reset_token(user_id: int, token: str, expires_at_iso: str):
    ph = _ph()
    conn = _connect()
    try:
        cur = _cursor(conn)
        cur.execute(
            f"INSERT INTO password_reset_tokens (user_id, token, expires_at, used) VALUES ({ph},{ph},{ph},0)",
            (user_id, token, expires_at_iso),
        )
        conn.commit()
    finally:
        _close(conn)


def verify_password_reset_token(token: str):
    ph = _ph()
    conn = _connect()
    try:
        cur = _cursor(conn)
        cur.execute(
            f"SELECT user_id, expires_at, used FROM password_reset_tokens WHERE token = {ph}",
            (token,),
        )
        row = _fetchrow(cur)
    finally:
        _close(conn)

    if not row:
        return None, "Invalid or expired password reset link."
    if row["used"]:
        return None, "This reset link has already been used."
    exp = datetime.fromisoformat(row["expires_at"])
    if datetime.now() > exp:
        return None, "This reset link has expired. Please request a new one."
    return row["user_id"], None


def consume_password_reset_token(token: str):
    ph = _ph()
    conn = _connect()
    try:
        cur = _cursor(conn)
        cur.execute(f"UPDATE password_reset_tokens SET used = 1 WHERE token = {ph}", (token,))
        conn.commit()
    finally:
        _close(conn)
