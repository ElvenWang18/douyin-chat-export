"""Test Argon2id password hashing and SHA-256 migration."""

import hashlib
import pytest
from backend.security.passwords import (
    hash_password, verify_password, hash_sha256,
    is_argon2_hash, is_sha256_hash, verify_and_migrate,
)


class TestArgon2id:
    def test_hash_format(self):
        h = hash_password("test-password")
        assert h.startswith("$argon2id$")
        assert is_argon2_hash(h)
    
    def test_verify_ok(self):
        h = hash_password("mySecurePass123")
        assert verify_password("mySecurePass123", h)
    
    def test_verify_wrong(self):
        h = hash_password("correct")
        assert not verify_password("wrong", h)
    
    def test_different_passwords_different_hashes(self):
        h1 = hash_password("alpha")
        h2 = hash_password("beta")
        assert h1 != h2


class TestLegacySHA256:
    def test_format(self):
        h = hash_sha256("test")
        assert len(h) == 64
        assert is_sha256_hash(h)
    
    def test_not_argon2(self):
        h = hash_sha256("test")
        assert not is_argon2_hash(h)


class TestMigration:
    def test_argon2_no_migration(self):
        h = hash_password("pass")
        ok, new = verify_and_migrate("pass", h)
        assert ok is True
        assert new is None
    
    def test_legacy_upgrade(self):
        h = hash_sha256("oldpass")
        ok, new = verify_and_migrate("oldpass", h)
        assert ok is True
        assert new is not None
        assert is_argon2_hash(new)
    
    def test_legacy_wrong_password(self):
        h = hash_sha256("oldpass")
        ok, new = verify_and_migrate("wrong", h)
        assert ok is False
        assert new is None
