"""File and directory permission management.

Sets restrictive umask and verifies directory permissions at startup.
"""

import os
import stat
import sys


def set_restrictive_umask() -> None:
    """Set umask to 077 so all new files default to 0600 and dirs to 0700."""
    os.umask(0o077)


def ensure_directory_permissions(
    path: str,
    mode: int = 0o700,
    warn_only: bool = False,
) -> None:
    """Create directory with restrictive permissions if it doesn't exist.
    
    Args:
        path: Directory path to check/create.
        mode: Permission mode (default 0700).
        warn_only: If True, only warn about incorrect perms instead of fixing.
    """
    if not os.path.exists(path):
        os.makedirs(path, mode=mode, exist_ok=True)
        return

    try:
        st = os.stat(path)
        current_mode = stat.S_IMODE(st.st_mode)
        if current_mode != mode:
            msg = (
                f"Directory '{path}' has permissions {current_mode:04o}, "
                f"expected {mode:04o}"
            )
            if warn_only:
                print(f"[WARNING] {msg}", file=sys.stderr)
            else:
                os.chmod(path, mode)
    except OSError as e:
        print(f"[WARNING] Cannot check/set permissions on '{path}': {e}", file=sys.stderr)


def ensure_file_permissions(
    path: str,
    mode: int = 0o600,
    warn_only: bool = False,
) -> None:
    """Verify or correct file permissions.
    
    Args:
        path: File path to check.
        mode: Permission mode (default 0600).
        warn_only: If True, only warn instead of fixing.
    """
    if not os.path.exists(path):
        return
    try:
        st = os.stat(path)
        current_mode = stat.S_IMODE(st.st_mode)
        if current_mode != mode:
            msg = (
                f"File '{path}' has permissions {current_mode:04o}, "
                f"expected {mode:04o}"
            )
            if warn_only:
                print(f"[WARNING] {msg}", file=sys.stderr)
            else:
                os.chmod(path, mode)
    except OSError as e:
        print(f"[WARNING] Cannot check/set permissions on '{path}': {e}", file=sys.stderr)


def initialize_all_permissions() -> None:
    """Apply restrictive permissions to all data directories and files.
    
    This is idempotent — safe to call on every startup.
    In Docker: most directories are pre-created by the entrypoint.
    On bare metal: ensures correct permissions regardless of umask history.
    """
    from common import paths

    # Directories that must exist
    for dir_path in [
        paths.DATA_DIR,
        paths.AUTH_DIR,
        paths.DATABASE_DIR,
        paths.BROWSER_PROFILE,
        paths.MEDIA_DIR,
        paths.EXPORT_DIR,
        paths.LOG_DIR,
        paths.CONFIG_DIR,
    ]:
        ensure_directory_permissions(dir_path, mode=0o700, warn_only=True)

    # Files that may exist
    for file_path in [
        paths.DB_PATH,
        paths.AUTH_DB_PATH,
        paths.CONFIG_PATH,
        paths.SCRAPE_LOG,
        paths.DISCOVER_LOG,
    ]:
        ensure_file_permissions(file_path, mode=0o600, warn_only=True)
