"""
auth.py
-------
User authentication helpers for the multi-tenant SaaS layer.

Provides:
  - User  — Flask-Login UserMixin backed by the `users` DB table
  - register_user()  — create a new account with hashed password
  - verify_user()    — validate credentials at login (checks is_active)
  - load_user()      — Flask-Login user_loader callback
"""

from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from modules import database


class User(UserMixin):
    """Lightweight wrapper around a `users` DB row for Flask-Login."""

    def __init__(self, row: dict):
        self.id           = row["id"]
        self.username     = row["username"]
        self.email        = row["email"]
        self.password_hash= row["password_hash"]
        self.created_at   = row.get("created_at", "")
        self.last_login   = row.get("last_login", "")
        self.is_admin     = bool(row.get("is_admin", 0))
        # is_active=1 means the account is enabled (default); 0 = suspended
        self.is_active_account = bool(row.get("is_active", 1))

    def get_id(self):
        return str(self.id)

    # Flask-Login checks this before allowing login — we repurpose it
    # to gate suspended accounts.  The attribute on UserMixin is `is_active`.
    @property
    def is_active(self):
        return self.is_active_account

    @staticmethod
    def from_id(user_id: int):
        row = database.get_user_by_id(int(user_id))
        return User(row) if row else None

    @staticmethod
    def from_username(username: str):
        row = database.get_user_by_username(username)
        return User(row) if row else None


def register_user(username: str, email: str, password: str):
    """
    Create a new user account.

    Returns (User, None) on success.
    Returns (None, error_message) if username/email already exists.
    """
    if database.get_user_by_username(username):
        return None, "Username is already taken."
    if database.get_user_by_email(email):
        return None, "An account with that email already exists."

    pw_hash = generate_password_hash(password)
    user_id = database.create_user(username, email, pw_hash)

    # First registered user (after super admin) gets their orphaned scans
    if database.count_users() == 1:
        database.migrate_existing_scans_to_user(user_id)

    database.update_last_login(user_id)
    row = database.get_user_by_id(user_id)
    return User(row), None


def verify_user(username_or_email: str, password: str):
    """
    Check credentials using username OR email (case-insensitive).

    Returns:
      User  — on success
      None  — on failure (wrong password or unknown identifier)
      "suspended" — if account is suspended (caller flashes a message)
    """
    identifier = (username_or_email or "").strip()
    if not identifier or not password:
        return None

    row = database.get_user_by_identifier(identifier)
    if not row:
        return None
    if not check_password_hash(row["password_hash"], password):
        return None

    # Check if account is active (is_active = 1 by default)
    if not row.get("is_active", 1):
        return "suspended"

    database.update_last_login(row["id"])
    row["last_login"] = (database.get_user_by_id(row["id"]) or {}).get("last_login", "")
    return User(row)


def load_user(user_id: str):
    """Flask-Login user_loader — called on every authenticated request."""
    return User.from_id(int(user_id))
