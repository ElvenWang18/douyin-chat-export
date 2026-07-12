"""CLI security tools for douyin-chat-export.

Usage:
  python -m backend.cli set-password
  python -m backend.cli revoke-sessions
  python -m backend.cli security-check
"""

import sys
import os

# Ensure repo root on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def _get_password_no_echo(prompt: str = "New password: ") -> str:
    """Read password without echoing."""
    import termios
    import tty

    sys.stderr.write(prompt)
    sys.stderr.flush()
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        pw = ""
        while True:
            c = sys.stdin.read(1)
            if c == "\n" or c == "\r\n" or c == "\r":
                sys.stderr.write("\n")
                break
            if c == "\x03":  # Ctrl-C
                sys.stderr.write("\n")
                raise KeyboardInterrupt
            if c == "\x7f":  # Backspace
                if pw:
                    pw = pw[:-1]
                    sys.stderr.write("\b \b")
            else:
                pw += c
                sys.stderr.write("*")
        sys.stderr.flush()
        return pw
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def cmd_set_password():
    """Set or change the admin password."""
    from backend.security.passwords import hash_password
    from backend.security.auth_db import set_stored_password_hash, get_stored_password_hash

    current = get_stored_password_hash()
    if current:
        old = _get_password_no_echo("Current password: ")
        from backend.security.passwords import verify_and_migrate
        ok, _ = verify_and_migrate(old, current)
        if not ok:
            print("ERROR: Incorrect current password.", file=sys.stderr)
            sys.exit(1)

    pw = _get_password_no_echo("New password: ")
    if len(pw) < 4:
        print("ERROR: Password too short (minimum 4 characters).", file=sys.stderr)
        sys.exit(1)

    confirm = _get_password_no_echo("Confirm new password: ")
    if pw != confirm:
        print("ERROR: Passwords do not match.", file=sys.stderr)
        sys.exit(1)

    h = hash_password(pw)
    set_stored_password_hash(h)

    # Remove legacy SHA-256 from config
    from common import config as _cfg
    cfg = _cfg.load_config()
    if cfg.get("password_hash"):
        cfg.pop("password_hash")
        _cfg.save_config(cfg)

    print("Password set successfully.")


def cmd_revoke_sessions():
    """Revoke all active sessions."""
    from backend.security.auth_db import revoke_all_sessions
    revoke_all_sessions()
    print("All sessions revoked.")


def cmd_security_check():
    """Run security startup checks."""
    from common.security_config import init_security_config, get_security_config
    from backend.security.startup_checks import run_startup_checks

    init_security_config()
    sec = get_security_config()

    print(f"APP_ENV: {sec.app_env}")
    print(f"Cookie Secure: {sec.cookie_secure}")
    print(f"Allow Insecure: {sec.allow_insecure_no_password}")
    print(f"Remote Login: {sec.enable_remote_login}")
    print(f"Cookie Import: {sec.enable_cookie_import}")
    print(f"Server酱: {sec.enable_serverchan}")
    print()

    try:
        run_startup_checks(sec)
        print("✓ All security checks passed.")
    except Exception as e:
        print(f"✗ {e}")
        sys.exit(1)


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m backend.cli <command>")
        print()
        print("Commands:")
        print("  set-password       Set or change admin password")
        print("  revoke-sessions    Revoke all active sessions")
        print("  security-check     Run security startup checks")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "set-password":
        cmd_set_password()
    elif cmd == "revoke-sessions":
        cmd_revoke_sessions()
    elif cmd == "security-check":
        cmd_security_check()
    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
