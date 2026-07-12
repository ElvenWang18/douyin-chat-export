"""Session management with HttpOnly cookies.

Generates random session tokens, stores only hashes,
manages lifecycle via secure cookies.
"""

import hashlib
import hmac
import os
import secrets
import time
from typing import Optional

from . import auth_db
from common.security_config import get_security_config

# Token entropy in bits
SESSION_TOKEN_BYTES = 32  # 256 bits
CSRF_TOKEN_BYTES = 32


def _hash_token(token: str) -> str:
    """Hash a token for storage (SHA-256, no salt needed for random tokens)."""
    return hashlib.sha256(token.encode()).hexdigest()


def generate_session_token() -> str:
    """Generate a cryptographically random session token."""
    return secrets.token_urlsafe(SESSION_TOKEN_BYTES)


def generate_csrf_token() -> str:
    """Generate a cryptographically random CSRF token."""
    return secrets.token_urlsafe(CSRF_TOKEN_BYTES)


def create_session(
    client_ip: str | None = None,
    user_agent: str | None = None,
    remember: bool = False,
) -> tuple[str, str, str]:
    """Create a new session and return (session_id, session_token, csrf_token).
    
    The session_token is the raw token sent via cookie.
    The csrf_token is returned to the frontend for CSRF headers.
    """
    sec = get_security_config()
    now = int(time.time())

    session_token = generate_session_token()
    csrf_token = generate_csrf_token()

    token_hash = _hash_token(session_token)
    csrf_hash = _hash_token(csrf_token)

    idle_ttl = sec.session_idle_ttl_seconds
    if remember:
        idle_ttl = sec.session_remember_ttl_seconds
    
    idle_expires = now + idle_ttl
    absolute_expires = now + (sec.session_remember_ttl_seconds if remember else sec.session_absolute_ttl_seconds)

    client_ip_hash = _hash_token(client_ip) if client_ip else None
    ua_hash = _hash_token(user_agent) if user_agent else None

    session_id = secrets.token_hex(16)

    auth_db.create_session_record(
        session_id=session_id,
        token_hash=token_hash,
        csrf_hash=csrf_hash,
        idle_expires_at=idle_expires,
        absolute_expires_at=absolute_expires,
        client_ip_hash=client_ip_hash,
        user_agent_hash=ua_hash,
    )

    return session_id, session_token, csrf_token


def validate_session_token(session_token: str) -> dict | None:
    """Validate a session token. Returns session dict or None."""
    token_hash = _hash_token(session_token)
    session = auth_db.get_session_by_token_hash(token_hash)
    if not session:
        return None
    
    now = int(time.time())
    if session["idle_expires_at"] < now:
        auth_db.revoke_session_by_id(session["id"])
        return None
    if session["absolute_expires_at"] < now:
        auth_db.revoke_session_by_id(session["id"])
        return None

    return session


def validate_csrf_token(session: dict, csrf_token: str) -> bool:
    """Validate a CSRF token against a session."""
    if not csrf_token:
        return False
    return hmac.compare_digest(session["csrf_hash"], _hash_token(csrf_token))


def refresh_session(session: dict) -> tuple[str, str | None]:
    """Refresh session idle timeout. Returns (session_id, new_csrf).
    
    Only writes to DB at most once per 60 seconds to reduce I/O.
    """
    sec = get_security_config()
    now = int(time.time())

    last_seen = session["last_seen_at"]
    if now - last_seen < 60:
        return session["id"], None

    idle_ttl = sec.session_idle_ttl_seconds
    # Check if this was a "remember me" session
    if session["absolute_expires_at"] - session["created_at"] > sec.session_absolute_ttl_seconds:
        idle_ttl = sec.session_remember_ttl_seconds

    new_idle_expires = now + idle_ttl
    auth_db.touch_session(session["id"], new_idle_expires)
    return session["id"], None


def revoke_session(session_token: str) -> None:
    """Revoke a session by token."""
    token_hash = _hash_token(session_token)
    session = auth_db.get_session_by_token_hash(token_hash)
    if session:
        auth_db.revoke_session_by_id(session["id"])


def revoke_all_other_sessions(current_session_id: str) -> None:
    """Revoke all sessions except the current one."""
    conn = auth_db.get_auth_db()
    now = int(time.time())
    conn.execute(
        "UPDATE sessions SET revoked_at = ? WHERE revoked_at IS NULL AND id != ?",
        (now, current_session_id),
    )
    conn.commit()
    conn.close()


def get_session_cookie_name() -> str:
    """Get the appropriate cookie name based on environment."""
    sec = get_security_config()
    if sec.is_production():
        return "__Host-dce_session"
    else:
        return "dce_session_dev"


def make_session_cookie(session_token: str, max_age: int) -> dict:
    """Build Set-Cookie parameters for the session cookie.
    
    Returns dict of cookie params suitable for fastapi Response.set_cookie().
    """
    sec = get_security_config()
    cookie_name = get_session_cookie_name()

    kwargs = {
        "key": cookie_name,
        "value": session_token,
        "path": "/",
        "httponly": True,
        "samesite": "strict",
        "max_age": max_age,
        "secure": sec.cookie_secure,
    }

    # __Host- prefix requires no Domain set
    if sec.is_production():
        pass  # No Domain
    else:
        kwargs.pop("domain", None)

    return kwargs


def clear_session_cookie() -> dict:
    """Build parameters to clear the session cookie."""
    sec = get_security_config()
    cookie_name = get_session_cookie_name()
    return {
        "key": cookie_name,
        "value": "",
        "path": "/",
        "httponly": True,
        "samesite": "strict",
        "max_age": 0,
        "secure": sec.cookie_secure,
    }
