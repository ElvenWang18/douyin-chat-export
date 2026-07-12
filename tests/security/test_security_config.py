"""Test security configuration parsing and validation."""

import os
import pytest
from common.security_config import SecurityConfig, _resolve_bool


class TestBooleanResolution:
    def test_true_lowercase(self):
        assert _resolve_bool("true", False) is True
    
    def test_false_lowercase(self):
        assert _resolve_bool("false", True) is False
    
    def test_none_returns_default(self):
        assert _resolve_bool(None, True) is True
        assert _resolve_bool(None, False) is False
    
    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            _resolve_bool("yes", False)
        with pytest.raises(ValueError):
            _resolve_bool("1", False)
        with pytest.raises(ValueError):
            _resolve_bool("", False)


class TestSecurityConfigDefaults:
    def test_development_defaults(self):
        os.environ["APP_ENV"] = "development"
        config = SecurityConfig.from_env()
        assert config.app_env == "development"
        assert config.cookie_secure is False
        assert config.enable_remote_login is False
        assert config.enable_cookie_import is False
    
    def test_production_defaults(self):
        os.environ["APP_ENV"] = "production"
        config = SecurityConfig.from_env()
        assert config.app_env == "production"
        assert config.cookie_secure is True
        assert config.allow_insecure_no_password is False
    
    def test_frozen_immutable(self):
        os.environ["APP_ENV"] = "development"
        config = SecurityConfig.from_env()
        with pytest.raises(Exception):
            config.cookie_secure = True
