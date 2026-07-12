"""Password hashing with Argon2id + legacy SHA-256 migration.

Uses argon2-cffi for secure password storage.
Supports smooth migration from old SHA-256 hashes.
"""

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash
import hashlib
import hmac

# Argon2id parameters tuned for ~100-500ms on typical hardware
_ph = PasswordHasher(
    time_cost=4,
    memory_cost=65536,  # 64 MB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


def hash_password(password: str) -> str:
    """Hash a password with Argon2id. Returns encoded hash string."""
    return _ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against an Argon2id hash."""
    try:
        return _ph.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return False


def hash_sha256(password: str) -> str:
    """Legacy SHA-256 hash for migration support only."""
    return hashlib.sha256(password.encode()).hexdigest()


def is_argon2_hash(hash_str: str) -> bool:
    """Check if hash string looks like an Argon2id hash."""
    return hash_str.startswith("$argon2id$")


def is_sha256_hash(hash_str: str) -> bool:
    """Check if hash string looks like a SHA-256 hex digest."""
    return len(hash_str) == 64 and all(c in "0123456789abcdef" for c in hash_str.lower())


def verify_and_migrate(password: str, stored_hash: str) -> tuple[bool, str | None]:
    """Verify password and return (ok, new_argon2_hash_or_None).
    
    If the stored hash is legacy SHA-256, verification succeeds,
    it returns the new Argon2id hash for upgrading.
    """
    if is_argon2_hash(stored_hash):
        return verify_password(password, stored_hash), None
    
    if is_sha256_hash(stored_hash):
        if not hmac.compare_digest(hash_sha256(password), stored_hash):
            return False, None
        # Upgrade: return new argon2 hash
        return True, hash_password(password)
    
    # Unknown format - try Argon2id anyway
    try:
        return _ph.verify(stored_hash, password), None
    except Exception:
        return False, None
