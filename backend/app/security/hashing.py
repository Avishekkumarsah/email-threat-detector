"""
backend/app/security/hashing.py
---------------------------------
Argon2id password hashing — replaces Werkzeug PBKDF2.
"""
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

_ph = PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16,
)


def hash_password(plain_password: str) -> str:
    """Hash a password using Argon2id. Returns the encoded hash string."""
    return _ph.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against an Argon2id hash or legacy Werkzeug hash."""
    if not hashed_password or not plain_password:
        return False
    if hashed_password.startswith(("scrypt:", "pbkdf2:")):
        try:
            from werkzeug.security import check_password_hash
            return check_password_hash(hashed_password, plain_password)
        except Exception:
            return False
    try:
        return _ph.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(hashed_password: str) -> bool:
    """Returns True if the hash parameters are outdated and should be rehashed."""
    return _ph.check_needs_rehash(hashed_password)
