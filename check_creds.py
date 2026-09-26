"""
check_creds.py
--------------
Run from the project root:  python check_creds.py
Tests every stored IMAP account. Never prints the password itself.
"""

import imaplib
from modules import database

creds = database.get_all_active_imap_credentials()
if not creds:
    print("No active IMAP accounts found in the database.")

for c in creds:
    try:
        pw = database.decrypt_password(c["encrypted_pass"])
    except Exception as e:
        print(f"user {c['user_id']}: CANNOT DECRYPT ({e}) -> SECRET_KEY changed?")
        continue

    print(f"user {c['user_id']} | {c['imap_email']} | {c['imap_host']}:{c['imap_port']} "
          f"| pass length={len(pw)} | has spaces={' ' in pw}")
    try:
        m = imaplib.IMAP4_SSL(c["imap_host"], int(c["imap_port"]), timeout=15)
        m.login(c["imap_email"], pw)
        print("   -> LOGIN OK")
        m.logout()
    except Exception as e:
        print(f"   -> LOGIN FAILED: {e}")