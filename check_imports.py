import sys

errors = []

try:
    import flask_login
    print(f"[OK] flask_login {flask_login.__version__}")
except Exception as e:
    errors.append(f"[FAIL] flask_login: {e}")

try:
    from cryptography.fernet import Fernet
    print("[OK] cryptography.fernet")
except Exception as e:
    errors.append(f"[FAIL] cryptography: {e}")

try:
    from werkzeug.security import generate_password_hash, check_password_hash
    print("[OK] werkzeug.security")
except Exception as e:
    errors.append(f"[FAIL] werkzeug.security: {e}")

try:
    import config
    print(f"[OK] config (SECRET_KEY set: {bool(config.SECRET_KEY)})")
except Exception as e:
    errors.append(f"[FAIL] config: {e}")

try:
    from modules import database
    database.init_db()
    print("[OK] modules.database - init_db() ran")
except Exception as e:
    errors.append(f"[FAIL] modules.database: {e}")

try:
    from modules.auth import User, register_user, verify_user
    print("[OK] modules.auth")
except Exception as e:
    errors.append(f"[FAIL] modules.auth: {e}")

try:
    from modules import inbox_monitor
    print("[OK] modules.inbox_monitor")
except Exception as e:
    errors.append(f"[FAIL] modules.inbox_monitor: {e}")

try:
    import app as flask_app
    print("[OK] app.py imported cleanly")
except Exception as e:
    errors.append(f"[FAIL] app.py: {e}")

print()
if errors:
    print("=== ERRORS ===")
    for err in errors:
        print(err)
    sys.exit(1)
else:
    print("=== ALL IMPORTS OK ===")
