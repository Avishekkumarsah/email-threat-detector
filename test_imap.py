import os
from dotenv import load_dotenv
import imaplib
import traceback

import sys
sys.stdout = open('test_output.txt', 'w')
sys.stderr = sys.stdout

load_dotenv()

user = os.getenv("IMAP_USER")
pwd = os.getenv("IMAP_PASS")

print(f"USER: {user}")
print(f"PASS LENGTH: {len(pwd) if pwd else 0}")
print("Connecting...")

try:
    conn = imaplib.IMAP4_SSL("imap.gmail.com", 993)
    conn.login(user, pwd)
    print("SUCCESS")
    conn.select("INBOX")
    status, data = conn.search(None, "UNSEEN")
    print(f"UNSEEN EMAILS: {data}")
    conn.logout()
except Exception as e:
    print(f"ERROR: {e}")
    traceback.print_exc()
