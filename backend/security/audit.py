"""Audit event recording for security-relevant operations."""

import json

from . import auth_db


def log_audit(
    event_type: str,
    result: str = "success",
    request_id: str | None = None,
    actor: str | None = None,
    client_ip_hash: str | None = None,
    target_type: str | None = None,
    target_count: int | None = None,
    detail: dict | None = None,
) -> None:
    """Record a security audit event.
    
    Args:
        event_type: e.g. LOGIN_SUCCESS, EXPORT_CREATED, etc.
        result: "success" or "failure"
        request_id: Correlation ID for tracing
        actor: Session ID or identifier (hashed)
        client_ip_hash: One-way hash of client IP
        target_type: What was acted upon (conversation, export, etc.)
        target_count: How many items
        detail: Additional non-sensitive context
    """
    detail_json = json.dumps(detail) if detail else None
    auth_db.record_audit_event(
        event_type=event_type,
        result=result,
        request_id=request_id,
        actor=actor,
        client_ip_hash=client_ip_hash,
        target_type=target_type,
        target_count=target_count,
        detail_json=detail_json,
    )
