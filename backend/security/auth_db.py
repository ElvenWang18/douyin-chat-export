"""Authentication database: credentials, sessions, audit, exports.

Separate from chat.db to isolate credentials from chat data.
"""

import os
import sqlite3
import time

from common import paths


def get_auth_db() -> sqlite3.Connection:
    """Open the auth database (creates + inits schema if needed)."""
    os.makedirs(os.path.dirname(paths.AUTH_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(paths.AUTH_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    _init_schema(conn)
    return conn


def _init_schema(conn: sqlite3.Connection):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS admin_credentials (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            password_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            token_hash TEXT NOT NULL UNIQUE,
            csrf_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            last_seen_at INTEGER NOT NULL,
            idle_expires_at INTEGER NOT NULL,
            absolute_expires_at INTEGER NOT NULL,
            elevated_until INTEGER,
            client_ip_hash TEXT,
            user_agent_hash TEXT,
            revoked_at INTEGER
        );

        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            result TEXT NOT NULL,
            request_id TEXT,
            actor TEXT,
            client_ip_hash TEXT,
            target_type TEXT,
            target_count INTEGER,
            detail_json TEXT
        );

        CREATE TABLE IF NOT EXISTS export_artifacts (
            id TEXT PRIMARY KEY,
            file_name TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            downloaded_at INTEGER,
            delete_after_download INTEGER NOT NULL,
            status TEXT NOT NULL,
            format TEXT,
            conversation_count INTEGER
        );
    """)
    conn.commit()


# ── Credential helpers ────────────────────────────────────────

def get_stored_password_hash() -> str | None:
    """Get the stored Argon2id password hash, or None."""
    conn = get_auth_db()
    row = conn.execute(
        "SELECT password_hash FROM admin_credentials WHERE id = 1"
    ).fetchone()
    conn.close()
    return row["password_hash"] if row else None


def set_stored_password_hash(password_hash: str) -> None:
    """Store a new password hash."""
    now = int(time.time())
    conn = get_auth_db()
    existing = conn.execute(
        "SELECT id FROM admin_credentials WHERE id = 1"
    ).fetchone()
    if existing:
        conn.execute(
            "UPDATE admin_credentials SET password_hash = ?, updated_at = ? WHERE id = 1",
            (password_hash, now),
        )
    else:
        conn.execute(
            "INSERT INTO admin_credentials (id, password_hash, created_at, updated_at) "
            "VALUES (1, ?, ?, ?)",
            (password_hash, now, now),
        )
    conn.commit()
    conn.close()


def clear_stored_password() -> None:
    """Remove the stored password hash."""
    conn = get_auth_db()
    conn.execute("DELETE FROM admin_credentials WHERE id = 1")
    conn.commit()
    conn.close()


# ── Session helpers ───────────────────────────────────────────

def create_session_record(
    session_id: str,
    token_hash: str,
    csrf_hash: str,
    idle_expires_at: int,
    absolute_expires_at: int,
    client_ip_hash: str | None = None,
    user_agent_hash: str | None = None,
) -> None:
    now = int(time.time())
    conn = get_auth_db()
    conn.execute(
        """INSERT INTO sessions
           (id, token_hash, csrf_hash, created_at, last_seen_at,
            idle_expires_at, absolute_expires_at, client_ip_hash, user_agent_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (session_id, token_hash, csrf_hash, now, now,
         idle_expires_at, absolute_expires_at, client_ip_hash, user_agent_hash),
    )
    conn.commit()
    conn.close()


def get_session_by_token_hash(token_hash: str) -> dict | None:
    conn = get_auth_db()
    row = conn.execute(
        "SELECT * FROM sessions WHERE token_hash = ? AND revoked_at IS NULL",
        (token_hash,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def touch_session(session_id: str, new_idle_expires: int) -> None:
    now = int(time.time())
    conn = get_auth_db()
    conn.execute(
        "UPDATE sessions SET last_seen_at = ?, idle_expires_at = ? WHERE id = ?",
        (now, new_idle_expires, session_id),
    )
    conn.commit()
    conn.close()


def revoke_session_by_id(session_id: str) -> None:
    now = int(time.time())
    conn = get_auth_db()
    conn.execute(
        "UPDATE sessions SET revoked_at = ? WHERE id = ?",
        (now, session_id),
    )
    conn.commit()
    conn.close()


def revoke_all_sessions() -> None:
    now = int(time.time())
    conn = get_auth_db()
    conn.execute("UPDATE sessions SET revoked_at = ? WHERE revoked_at IS NULL", (now,))
    conn.commit()
    conn.close()


def purge_expired_sessions() -> int:
    now = int(time.time())
    conn = get_auth_db()
    cur = conn.execute(
        "DELETE FROM sessions WHERE absolute_expires_at < ? OR revoked_at IS NOT NULL",
        (now,),
    )
    count = cur.rowcount
    conn.commit()
    conn.close()
    return count


# ── Audit helpers ─────────────────────────────────────────────

def record_audit_event(
    event_type: str,
    result: str,
    request_id: str | None = None,
    actor: str | None = None,
    client_ip_hash: str | None = None,
    target_type: str | None = None,
    target_count: int | None = None,
    detail_json: str | None = None,
) -> None:
    now = int(time.time())
    conn = get_auth_db()
    conn.execute(
        """INSERT INTO audit_events
           (created_at, event_type, result, request_id, actor,
            client_ip_hash, target_type, target_count, detail_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (now, event_type, result, request_id, actor,
         client_ip_hash, target_type, target_count, detail_json),
    )
    conn.commit()
    conn.close()


# ── Export artifact helpers ───────────────────────────────────

def create_export_record(
    export_id: str,
    file_name: str,
    expires_at: int,
    delete_after_download: bool,
    format: str | None = None,
    conversation_count: int | None = None,
) -> None:
    now = int(time.time())
    conn = get_auth_db()
    conn.execute(
        """INSERT INTO export_artifacts
           (id, file_name, created_at, expires_at, delete_after_download, status, format, conversation_count)
           VALUES (?, ?, ?, ?, ?, 'completed', ?, ?)""",
        (export_id, file_name, now, expires_at, int(delete_after_download), format, conversation_count),
    )
    conn.commit()
    conn.close()


def get_export_record(export_id: str) -> dict | None:
    conn = get_auth_db()
    row = conn.execute(
        "SELECT * FROM export_artifacts WHERE id = ? AND status != 'deleted'",
        (export_id,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def mark_export_downloaded(export_id: str) -> None:
    now = int(time.time())
    conn = get_auth_db()
    conn.execute(
        "UPDATE export_artifacts SET downloaded_at = ? WHERE id = ?",
        (now, export_id),
    )
    conn.commit()
    conn.close()


def mark_export_deleted(export_id: str) -> None:
    conn = get_auth_db()
    conn.execute(
        "UPDATE export_artifacts SET status = 'deleted' WHERE id = ?",
        (export_id,),
    )
    conn.commit()
    conn.close()


def get_expired_exports() -> list[dict]:
    now = int(time.time())
    conn = get_auth_db()
    rows = conn.execute(
        "SELECT * FROM export_artifacts WHERE expires_at < ? AND status = 'completed'",
        (now,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def cleanup_expired_exports() -> int:
    """Delete expired export records from DB. Returns count."""
    now = int(time.time())
    conn = get_auth_db()
    cur = conn.execute(
        "UPDATE export_artifacts SET status = 'deleted' WHERE expires_at < ? AND status = 'completed'",
        (now,),
    )
    count = cur.rowcount
    conn.commit()
    conn.close()
    return count
