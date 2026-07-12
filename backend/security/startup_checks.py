"""Fail-closed startup checks for production deployments.

Ensures the application refuses to start if critical security
preconditions are not met, preventing accidental data exposure.
"""

import os
import stat
import sys

from common.security_config import SecurityConfig, get_security_config
from common import paths


class StartupCheckFailed(RuntimeError):
    """Raised when a security startup check fails."""
    pass


def _check_password_configured(sec: SecurityConfig) -> None:
    """Production must have a password hash."""
    if not sec.is_production():
        return
    from common.config import load_config
    from backend.security.auth_db import get_stored_password_hash

    # Check both legacy config and new auth DB
    cfg = load_config()
    has_legacy = bool(cfg.get("password_hash"))
    has_auth = bool(get_stored_password_hash())

    if not has_legacy and not has_auth:
        raise StartupCheckFailed(
            "APP_ENV=production but no admin password is set. "
            "Use the control panel or CLI to set a password first, "
            "or set ALLOW_INSECURE_NO_PASSWORD=*** to explicitly "
            "accept the risk (NOT recommended)."
        )


def _check_no_insecure_password_mode(sec: SecurityConfig) -> None:
    """Production must not allow insecure no-password mode."""
    if not sec.is_production():
        return
    if sec.allow_insecure_no_password:
        raise StartupCheckFailed(
            "APP_ENV=production and ALLOW_INSECURE_NO_PASSWORD=true. "
            "This combination exposes all your chat data without any "
            "authentication. Set a password instead."
        )


def _check_app_secret_key(sec: SecurityConfig) -> None:
    """Production must have a non-trivial secret key."""
    if not sec.is_production():
        return
    if len(sec.app_secret_key) < 16:
        raise StartupCheckFailed(
            "APP_ENV=production but APP_SECRET_KEY is too short "
            "(minimum 16 characters). Generate a strong key."
        )


def _check_cookie_secure(sec: SecurityConfig) -> None:
    """Production must use Secure cookies."""
    if not sec.is_production():
        return
    if not sec.cookie_secure:
        raise StartupCheckFailed(
            "APP_ENV=production but COOKIE_SECURE=false. "
            "Session cookies must be marked Secure in production "
            "to prevent theft over unencrypted connections."
        )


def _check_data_directory_permissions(sec: SecurityConfig) -> None:
    """Warn (dev) or fail (prod) if data directory has overly permissive modes."""
    for path, is_dir in [
        (paths.DATA_DIR, True),
        (paths.DB_PATH, False),
        (paths.CONFIG_PATH, False),
    ]:
        if not os.path.exists(path):
            continue
        try:
            st = os.stat(path)
            mode = stat.S_IMODE(st.st_mode)
            # Check if group or other have any permissions
            has_group = bool(mode & 0o070)
            has_other = bool(mode & 0o007)
            if has_group or has_other:
                msg = (
                    f"Data path '{path}' has overly permissive permissions "
                    f"({mode:04o}). Expected 0700 for dirs, 0600 for files. "
                    f"Run: chmod {'0700' if is_dir else '0600'} {path}"
                )
                if sec.is_production():
                    raise StartupCheckFailed(msg)
                else:
                    print(f"[WARNING] {msg}", file=sys.stderr)
        except OSError:
            pass  # can't stat, skip check


def _check_secret_file_permissions(sec: SecurityConfig) -> None:
    """If APP_SECRET_KEY_FILE is used, verify it's not world-readable."""
    secret_file = os.getenv("APP_SECRET_KEY_FILE", "")
    if not secret_file or not os.path.exists(secret_file):
        return
    try:
        st = os.stat(secret_file)
        mode = stat.S_IMODE(st.st_mode)
        if mode & 0o007:  # other-read
            raise StartupCheckFailed(
                f"Secret key file '{secret_file}' is world-readable "
                f"({mode:04o}). Fix: chmod 600 {secret_file}"
            )
    except StartupCheckFailed:
        raise
    except OSError:
        pass


def _check_dangerous_public_features(sec: SecurityConfig) -> None:
    """Check for dangerous combinations in production."""
    if not sec.is_production():
        return
    warnings = []
    if sec.enable_remote_login:
        warnings.append(
            "ENABLE_REMOTE_LOGIN=true in production exposes browser-based "
            "Douyin login to anyone who can reach the control panel."
        )
    if sec.enable_cookie_import:
        warnings.append(
            "ENABLE_COOKIE_IMPORT=true in production allows importing "
            "session cookies from untrusted sources."
        )
    if sec.enable_serverchan:
        warnings.append(
            "ENABLE_SERVERCHAN=true in production sends notifications "
            "to a third-party service."
        )
    if warnings:
        for w in warnings:
            print(f"[WARNING] {w}", file=sys.stderr)


def run_startup_checks(sec: SecurityConfig | None = None) -> None:
    """Execute all startup security checks.

    Args:
        sec: SecurityConfig instance or None (uses cached singleton).

    Raises:
        StartupCheckFailed: If a critical check fails.
    """
    if sec is None:
        sec = get_security_config()

    checks = [
        _check_password_configured,
        _check_no_insecure_password_mode,
        _check_app_secret_key,
        _check_cookie_secure,
        _check_data_directory_permissions,
        _check_secret_file_permissions,
        _check_dangerous_public_features,
    ]

    errors = []
    for check in checks:
        try:
            check(sec)
        except StartupCheckFailed as e:
            if sec.is_production():
                errors.append(str(e))
            else:
                print(f"[WARNING] {e}", file=sys.stderr)

    if errors:
        msg = "\n".join(errors)
        raise StartupCheckFailed(
            f"Security startup checks failed ({len(errors)} issue(s)):\n{msg}"
        )

    # Development mode warning
    if sec.is_development():
        print(
            "[WARNING] APP_ENV=development — authentication will be relaxed. "
            "Do NOT use this in production or on public networks.",
            file=sys.stderr,
        )
        if not sec.enable_remote_login:
            print(
                "[INFO] Remote login is disabled in development by default. "
                "Set ENABLE_REMOTE_LOGIN=true to enable.",
                file=sys.stderr,
            )
