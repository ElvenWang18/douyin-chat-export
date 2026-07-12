"""Structured logging with sensitive data redaction.

Provides a unified redaction function and structured log helpers.
"""

import re
import json
from datetime import datetime, timezone

# Patterns that must never appear in logs
_SENSITIVE_PATTERNS = [
    # sessionid cookie
    (r'sessionid[=:]\s*["\']?[a-f0-9]{32,}', '[REDACTED sessionid]'),
    (r'sessionid_ss[=:]\s*["\']?[a-f0-9]{32,}', '[REDACTED sessionid_ss]'),
    # Bearer tokens
    (r'Bearer\s+[A-Za-z0-9_\-\.=]{20,}', '[REDACTED Bearer]'),
    (r'Authorization[=:]\s*["\']?Bearer\s+[^\s"\']+', '[REDACTED Authorization]'),
    # SendKey (SCT prefix)
    (r'SCT[0-9]{6,}T[0-9a-zA-Z]{10,}', '[REDACTED SendKey]'),
    # CSRF tokens
    (r'X-CSRF-Token[=:]\s*["\']?[^\s"\',&]+', '[REDACTED CSRF]'),
    # Generic token patterns in URLs
    (r'[?&]token=[^&\s"\']+', '?token=[REDACTED]'),
    # Cookie header values
    (r'Cookie[=:]\s*["\']?[^"\']{20,}', '[REDACTED Cookie]'),
    # Signature URL params (common sign/ts patterns)
    (r'[?&](?:sign|signature|sig)=[^&\s"\']+', '&sign=[REDACTED]'),
    # UID (numeric IDs in URLs)
    # - handled more carefully to avoid false positives
]

# UID pattern: appears as isolated numeric strings in certain contexts
_UID_PATTERNS = [
    (r'"uid":\s*"[0-9]{10,}"', '"uid":"[REDACTED UID]"'),
    (r'"sender_uid":\s*"[0-9]{10,}"', '"sender_uid":"[REDACTED UID]"'),
]


def redact_sensitive(value: str) -> str:
    """Apply all redaction patterns to a string value.
    
    Handles strings, dicts (via JSON), and exceptions.
    """
    if isinstance(value, dict):
        try:
            value = json.dumps(value, ensure_ascii=False, default=str)
        except Exception:
            value = str(value)
    elif not isinstance(value, str):
        value = str(value)

    for pattern, replacement in _SENSITIVE_PATTERNS:
        value = re.sub(pattern, replacement, value, flags=re.IGNORECASE)

    for pattern, replacement in _UID_PATTERNS:
        value = re.sub(pattern, replacement, value)

    return value


def structured_log(level: str, event: str, **kwargs) -> str:
    """Produce a JSON log line, with automatic redaction.
    
    Args:
        level: INFO, WARNING, ERROR
        event: Event name (e.g. SCRAPE_COMPLETED)
        **kwargs: Additional context (sensitive values auto-redacted)
    """
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "event": event,
    }
    # Redact all values
    for key, val in kwargs.items():
        if isinstance(val, str) and any(p in val.lower() for p in (
            "sessionid", "token", "bearer", "cookie", "password", "secret", "sign",
        )):
            log_entry[key] = redact_sensitive(val)
        elif isinstance(val, (dict, list)):
            log_entry[key] = json.loads(redact_sensitive(json.dumps(val, default=str)))
        else:
            log_entry[key] = val

    return json.dumps(log_entry, ensure_ascii=False)


def safe_format_exception(exc: Exception) -> str:
    """Format an exception message without sensitive data."""
    msg = str(exc)
    return redact_sensitive(msg)
