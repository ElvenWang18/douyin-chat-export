"""Test session token generation and validation."""

import time
from backend.security.sessions import (
    _hash_token, generate_session_token, generate_csrf_token,
    create_session, validate_session_token, validate_csrf_token,
    revoke_session,
)


class TestTokenGeneration:
    def test_session_token_unique(self):
        t1 = generate_session_token()
        t2 = generate_session_token()
        assert t1 != t2
        assert len(t1) > 32
    
    def test_csrf_token_unique(self):
        t1 = generate_csrf_token()
        t2 = generate_csrf_token()
        assert t1 != t2


class TestHashing:
    def test_hash_deterministic(self):
        h1 = _hash_token("test-token")
        h2 = _hash_token("test-token")
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex
    
    def test_hash_different(self):
        assert _hash_token("a") != _hash_token("b")


class TestSessionLifecycle:
    def test_create_and_validate(self):
        sid, token, csrf = create_session()
        session = validate_session_token(token)
        assert session is not None
        assert session["id"] == sid
    
    def test_csrf_validation(self):
        sid, token, csrf = create_session()
        session = validate_session_token(token)
        assert validate_csrf_token(session, csrf)
        assert not validate_csrf_token(session, "wrong-csrf")
    
    def test_revoke(self):
        sid, token, csrf = create_session()
        revoke_session(token)
        assert validate_session_token(token) is None
    
    def test_wrong_token(self):
        create_session()
        assert validate_session_token("nonexistent-token") is None
