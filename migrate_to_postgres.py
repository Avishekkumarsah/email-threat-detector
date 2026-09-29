"""
migrate_to_postgres.py
-----------------------
One-shot migration script: copies all data from the local SQLite database
(scans.db) to a PostgreSQL database specified by DATABASE_URL.

Usage:
  1. Set DATABASE_URL in your .env file:
       DATABASE_URL=postgresql://user:password@localhost:5432/email_threat_db
  2. Run this script ONCE:
       python migrate_to_postgres.py
  3. Verify the data in PostgreSQL, then keep DATABASE_URL set in .env.

The script is safe to re-run — it will skip rows that already exist.
"""

import os
import sys
import sqlite3
import json
from pathlib import Path

# Load env before importing config
from dotenv import load_dotenv
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "")
DB_PATH = Path(__file__).parent / "scans.db"


def abort(msg):
    print(f"\n❌  {msg}", file=sys.stderr)
    sys.exit(1)


def connect_sqlite():
    if not DB_PATH.exists():
        abort(f"SQLite database not found: {DB_PATH}")
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def connect_postgres():
    try:
        import psycopg2
        import psycopg2.extras
    except ImportError:
        abort("psycopg2-binary is not installed. Run: pip install psycopg2-binary")
    try:
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = False
        return conn
    except Exception as e:
        abort(f"Cannot connect to PostgreSQL: {e}")


def main():
    if not DATABASE_URL:
        abort(
            "DATABASE_URL is not set in .env.\n"
            "  Add: DATABASE_URL=postgresql://user:pass@localhost:5432/dbname"
        )

    print("=" * 60)
    print("  Email Threat Detector — SQLite → PostgreSQL Migration")
    print("=" * 60)
    print(f"  SQLite source : {DB_PATH}")
    print(f"  PostgreSQL URL: {DATABASE_URL[:40]}...")
    print()

    # ── First, init the schema on Postgres ───────────────────────────────────
    print("▶ Initialising PostgreSQL schema …")
    import config
    from modules import database as db
    db.init_db()
    db.ensure_super_admin()
    print("  ✓ Schema ready")

    sq = connect_sqlite()
    pg = connect_postgres()
    import psycopg2.extras
    pg_cur = pg.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # ── Migrate users ────────────────────────────────────────────────────────
    print("\n▶ Migrating users …")
    users = sq.execute("SELECT * FROM users").fetchall()
    ok = skip = 0
    for u in users:
        try:
            pg_cur.execute("""
                INSERT INTO users (id, username, email, password_hash, created_at,
                                   last_login, is_admin, is_active)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (id) DO NOTHING
            """, (
                u["id"], u["username"], u["email"], u["password_hash"],
                u["created_at"],
                u["last_login"] if "last_login" in u.keys() else None,
                u["is_admin"] if "is_admin" in u.keys() else 0,
                u["is_active"] if "is_active" in u.keys() else 1,
            ))
            if pg_cur.rowcount:
                ok += 1
            else:
                skip += 1
        except Exception as e:
            print(f"  ⚠ User {u['id']} ({u['username']}): {e}")
    pg.commit()
    # Re-sequence serial
    pg_cur.execute("SELECT setval('users_id_seq', (SELECT MAX(id) FROM users))")
    pg.commit()
    print(f"  ✓ {ok} inserted, {skip} skipped")

    # ── Migrate imap_credentials ─────────────────────────────────────────────
    print("\n▶ Migrating IMAP credentials …")
    rows = sq.execute("SELECT * FROM imap_credentials").fetchall()
    ok = skip = 0
    for r in rows:
        try:
            pg_cur.execute("""
                INSERT INTO imap_credentials
                    (id, user_id, imap_host, imap_port, imap_email, encrypted_pass, is_active)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (id) DO NOTHING
            """, (r["id"], r["user_id"], r["imap_host"], r["imap_port"],
                  r["imap_email"], r["encrypted_pass"], r["is_active"]))
            if pg_cur.rowcount:
                ok += 1
            else:
                skip += 1
        except Exception as e:
            print(f"  ⚠ Credential {r['id']}: {e}")
    pg.commit()
    try:
        pg_cur.execute("SELECT setval('imap_credentials_id_seq', (SELECT MAX(id) FROM imap_credentials))")
        pg.commit()
    except Exception:
        pass
    print(f"  ✓ {ok} inserted, {skip} skipped")

    # ── Migrate scans ─────────────────────────────────────────────────────────
    print("\n▶ Migrating scans …")
    scans = sq.execute("SELECT * FROM scans").fetchall()
    ok = skip = 0
    for s in scans:
        try:
            pg_cur.execute("""
                INSERT INTO scans
                    (id, filename, scan_date, file_hash, sender, subject,
                     final_score, verdict, full_result_json, user_id)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (id) DO NOTHING
            """, (
                s["id"], s["filename"], s["scan_date"], s["file_hash"],
                s["sender"], s["subject"], s["final_score"], s["verdict"],
                s["full_result_json"],
                s["user_id"] if "user_id" in s.keys() else None,
            ))
            if pg_cur.rowcount:
                ok += 1
            else:
                skip += 1
        except Exception as e:
            print(f"  ⚠ Scan {s['id']}: {e}")
    pg.commit()
    try:
        pg_cur.execute("SELECT setval('scans_id_seq', (SELECT MAX(id) FROM scans))")
        pg.commit()
    except Exception:
        pass
    print(f"  ✓ {ok} inserted, {skip} skipped")

    # ── Migrate password_reset_tokens ────────────────────────────────────────
    print("\n▶ Migrating password reset tokens …")
    try:
        tokens = sq.execute("SELECT * FROM password_reset_tokens").fetchall()
        ok = skip = 0
        for t in tokens:
            pg_cur.execute("""
                INSERT INTO password_reset_tokens (id, user_id, token, expires_at, used)
                VALUES (%s,%s,%s,%s,%s)
                ON CONFLICT (id) DO NOTHING
            """, (t["id"], t["user_id"], t["token"], t["expires_at"], t["used"]))
            if pg_cur.rowcount:
                ok += 1
            else:
                skip += 1
        pg.commit()
        print(f"  ✓ {ok} inserted, {skip} skipped")
    except Exception as e:
        print(f"  ⚠ Tokens table skipped: {e}")

    sq.close()
    pg_cur.close()
    pg.close()

    print("\n" + "=" * 60)
    print("  ✅  Migration complete!")
    print("  The app will now use PostgreSQL automatically.")
    print("  Keep DATABASE_URL set in your .env file.")
    print("=" * 60)


if __name__ == "__main__":
    main()
