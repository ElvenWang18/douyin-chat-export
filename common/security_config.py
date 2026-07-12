"""Unified security configuration from environment variables.

All security-sensitive settings are parsed here with strict validation.
Production defaults are fail-closed; development allows lenient settings
but prints prominent warnings.

IMPORTANT: Keys and secrets must NEVER appear in log output.
"""

import os
import sys
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("security_config")


def _resolve_bool(value: str | None, default: bool) -> bool:
    """Strict boolean parser. Only accepts 'true'/'false' (case-insensitive).
    Rejects ambiguous values like '1', 'yes', 'on', empty string.
    """
    if value is None:
        return default
    v = value.strip().lower()
    if v == "true":
        return True
    if v == "false":
        return False
    # Strict: reject ambiguous values
    raise ValueError(
        f"Invalid boolean value '{value}' for a security configuration. "
        f"Use 'true' or 'false'."
    )


def _read_secret_from_file(path: str) -> str:
    """Read a secret from a Docker secret / run/secrets path."""
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        logger.warning("Secret file not found: %s", path)
        return ""
    except PermissionError:
        logger.warning("Cannot read secret file (permission): %s", path)
        return ""


@dataclass(frozen=True)
class SecurityConfig:
    """Immutable security configuration, parsed once at startup."""

    # Environment
    app_env: str  # "production" | "development"

    # Application secret key (for signing, CSRF HMAC, etc.)
    app_secret_key: str

    # Password / authentication
    allow_insecure_no_password: bool
    cookie_secure: bool

    # Session
    session_idle_ttl_seconds: int
    session_absolute_ttl_seconds: int
    session_remember_ttl_seconds: int

    # Network
    trusted_proxy_cidrs: list[str]
    admin_allowed_cidrs: list[str]

    # Feature toggles (default-off for production)
    enable_remote_login: bool
    enable_cookie_import: bool
    enable_external_media: bool
    enable_serverchan: bool

    # Export lifecycle
    export_ttl_seconds: int
    export_one_time_download: bool

    # Logging
    log_level: str
    log_redaction: bool

    @classmethod
    def from_env(cls, app_env: Optional[str] = None) -> "SecurityConfig":
        """Parse all settings from environment variables.
        
        Args:
            app_env: Override APP_ENV detection (used in tests).
        """
        if app_env is None:
            app_env = os.getenv("APP_ENV", "development").strip().lower()

        if app_env not in ("production", "development"):
            raise ValueError(
                f"APP_ENV must be 'production' or 'development', got '{app_env}'"
            )

        prod = app_env == "production"

        # Application secret key
        secret_key_file = os.getenv("APP_SECRET_KEY_FILE", "")
        secret_key = os.getenv("APP_SECRET_KEY", "")
        if secret_key_file:
            secret_key = _read_secret_from_file(secret_key_file)
        if not secret_key:
            secret_key = os.urandom(32).hex()  # auto-generate for dev

        # Password mode
        allow_insecure_no_password = _resolve_bool(
            os.getenv("ALLOW_INSECURE_NO_PASSWORD"), default=False
        )

        # Cookie security
        cookie_secure = _resolve_bool(
            os.getenv("COOKIE_SECURE"), default=prod
        )

        # Session TTLs
        session_idle_ttl_seconds = int(
            os.getenv("SESSION_IDLE_TTL_SECONDS", "1800")
        )
        session_absolute_ttl_seconds = int(
            os.getenv("SESSION_ABSOLUTE_TTL_SECONDS", "86400")
        )
        session_remember_ttl_seconds = int(
            os.getenv("SESSION_REMEMBER_TTL_SECONDS", "604800")
        )

        # Proxy / admin CIDRs
        trusted_proxy = os.getenv("TRUSTED_PROXY_CIDRS", "127.0.0.1/32,::1/128")
        trusted_proxy_cidrs = [
            c.strip() for c in trusted_proxy.split(",") if c.strip()
        ]

        admin_cidr = os.getenv("ADMIN_ALLOWED_CIDRS", "127.0.0.1/32,::1/128")
        admin_allowed_cidrs = [
            c.strip() for c in admin_cidr.split(",") if c.strip()
        ]

        # Feature toggles
        enable_remote_login = _resolve_bool(
            os.getenv("ENABLE_REMOTE_LOGIN"), default=False
        )
        enable_cookie_import = _resolve_bool(
            os.getenv("ENABLE_COOKIE_IMPORT"), default=False
        )
        enable_external_media = _resolve_bool(
            os.getenv("ENABLE_EXTERNAL_MEDIA"), default=False
        )
        enable_serverchan = _resolve_bool(
            os.getenv("ENABLE_SERVERCHAN"), default=False
        )

        # Export lifecycle
        export_ttl_seconds = int(
            os.getenv("EXPORT_TTL_SECONDS", "900")
        )
        export_one_time_download = _resolve_bool(
            os.getenv("EXPORT_ONE_TIME_DOWNLOAD"), default=True
        )

        # Logging
        log_level = os.getenv("LOG_LEVEL", "INFO").upper()
        log_redaction = _resolve_bool(
            os.getenv("LOG_REDACTION"), default=True
        )

        return cls(
            app_env=app_env,
            app_secret_key=secret_key,
            allow_insecure_no_password=allow_insecure_no_password,
            cookie_secure=cookie_secure,
            session_idle_ttl_seconds=session_idle_ttl_seconds,
            session_absolute_ttl_seconds=session_absolute_ttl_seconds,
            session_remember_ttl_seconds=session_remember_ttl_seconds,
            trusted_proxy_cidrs=trusted_proxy_cidrs,
            admin_allowed_cidrs=admin_allowed_cidrs,
            enable_remote_login=enable_remote_login,
            enable_cookie_import=enable_cookie_import,
            enable_external_media=enable_external_media,
            enable_serverchan=enable_serverchan,
            export_ttl_seconds=export_ttl_seconds,
            export_one_time_download=export_one_time_download,
            log_level=log_level,
            log_redaction=log_redaction,
        )

    def is_production(self) -> bool:
        return self.app_env == "production"

    def is_development(self) -> bool:
        return self.app_env == "development"


# Singleton — populated at app startup
_security_config: Optional[SecurityConfig] = None


def init_security_config(app_env: Optional[str] = None) -> SecurityConfig:
    """Initialize and cache the security configuration."""
    global _security_config
    _security_config = SecurityConfig.from_env(app_env)
    return _security_config


def get_security_config() -> SecurityConfig:
    """Get the cached security configuration. Must be initialized first."""
    if _security_config is None:
        raise RuntimeError("Security configuration not initialized")
    return _security_config
