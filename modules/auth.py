"""
auth.py
-------
User authentication helpers for the multi-tenant SaaS layer.

Provides:
  - User  — Flask-Login UserMixin backed by the `users` DB table
  - register_user()  — create a new account with hashed password
  - verify_user()    — validate credentials at login
  - load_user()      — Flask-Login user_loader callback
"""

from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from modules import database


class User(UserMixin):
    """Lightweight wrapper around a `users` DB row for Flask-Login."""

    def __init__(self, row: dict):
        self.id = row["id"]
        self.username = row["username"]
        self.email = row["email"]
        self.password_hash = row["password_hash"]
        self.created_at = row.get("created_at", "")
        self.is_admin = bool(row.get("is_admin", 0))

    def get_id(self):
        return str(self.id)

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

    # First registered user becomes admin — migrate orphaned scans to them
    if database.count_users() == 1:
        database.migrate_existing_scans_to_user(user_id)

    row = database.get_user_by_id(user_id)
    return User(row), None


def verify_user(username: str, password: str):
    """
    Check credentials.

    Returns User on success, None on failure.
    """
    row = database.get_user_by_username(username)
    if not row:
        return None
    if not check_password_hash(row["password_hash"], password):
        return None
    return User(row)


def load_user(user_id: str):
    """Flask-Login user_loader — called on every authenticated request."""
    return User.from_id(int(user_id))
