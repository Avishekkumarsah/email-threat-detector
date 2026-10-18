"""
backend/scripts/migrate_neon_schema.py
---------------------------------------
Safely applies missing columns, creates new tables, and backfills 
existing scans from 'scans' into 'email_scans'.
"""
import os
import sys
import json
import logging
from datetime import datetime, timezone

# Add workspace root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from sqlalchemy import text
from backend.app.database.session import engine, Base
import backend.app.models  # ensure all models are imported

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("migration")


def run_migration():
    logger.info("Starting Neon DB schema migration...")
    
    with engine.connect() as conn:
        trans = conn.begin()
        try:
            # 1. Add missing columns to users if they don't exist
            logger.info("Checking users table columns...")
            conn.execute(text("""
                ALTER TABLE users ADD COLUMN IF NOT EXISTS name VARCHAR(128) DEFAULT '';
                ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) DEFAULT 'user';
                ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();
            """))

            # Populate name and role from existing data
            conn.execute(text("""
                UPDATE users SET name = username WHERE name IS NULL OR name = '';
                UPDATE users SET role = 'admin' WHERE is_admin = 1 AND (role IS NULL OR role = 'user');
            """))

            # 2. Add missing columns to imap_credentials
            logger.info("Checking imap_credentials columns...")
            conn.execute(text("""
                ALTER TABLE imap_credentials ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();
                ALTER TABLE imap_credentials ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();
            """))

            # 3. Create all new SQLAlchemy tables if they do not exist
            logger.info("Creating new tables (email_scans, scan_findings, extracted_urls, etc.)...")
            Base.metadata.create_all(bind=conn)

            # 4. Migrate data from old scans to email_scans if scans table exists
            logger.info("Checking if old scans table needs to be backfilled into email_scans...")
            has_scans = conn.execute(text("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_name = 'scans'
                );
            """)).scalar()

            if has_scans:
                count_old = conn.execute(text("SELECT count(*) FROM scans")).scalar()
                count_new = conn.execute(text("SELECT count(*) FROM email_scans")).scalar()
                logger.info(f"Old scans: {count_old}, New email_scans: {count_new}")

                if count_old > 0 and count_new == 0:
                    logger.info("Migrating old scans into email_scans...")
                    conn.execute(text("""
                        INSERT INTO email_scans (
                            id, user_id, original_filename, file_hash, sender, subject,
                            overall_risk, classification, model_score, full_result_json,
                            scan_status, store_body, created_at, completed_at, scoring_rule_version
                        )
                        SELECT 
                            id,
                            user_id,
                            filename,
                            file_hash,
                            sender,
                            subject,
                            CASE 
                                WHEN verdict = 'Dangerous' THEN 'Critical Risk'
                                WHEN verdict = 'Suspicious' THEN 'Medium Risk'
                                WHEN verdict = 'Safe' THEN 'Low Risk'
                                ELSE 'Low Risk'
                            END,
                            CASE 
                                WHEN verdict = 'Dangerous' THEN 'Likely Phishing'
                                WHEN verdict = 'Suspicious' THEN 'Suspicious'
                                WHEN verdict = 'Safe' THEN 'Likely Legitimate'
                                ELSE 'Likely Legitimate'
                            END,
                            final_score,
                            full_result_json,
                            'completed',
                            FALSE,
                            NOW(),
                            NOW(),
                            '2.0'
                        FROM scans
                        ON CONFLICT (id) DO NOTHING;
                    """))
                    # Update sequence
                    conn.execute(text("""
                        SELECT setval(pg_get_serial_sequence('email_scans', 'id'), coalesce(max(id), 1)) FROM email_scans;
                    """))
                    logger.info("Old scans successfully migrated!")

            trans.commit()
            logger.info("Schema migration completed successfully!")

        except Exception as e:
            trans.rollback()
            logger.error(f"Migration error: {e}")
            raise


if __name__ == "__main__":
    run_migration()
