"""Rate limiting for login and sensitive endpoints.

Tracks attempts in-memory with IP-based bucketing.
Not persisted across restarts (acceptable for DoS mitigation).
"""

import time
import threading
from collections import defaultdict


class RateLimiter:
    """Simple in-memory sliding-window rate limiter."""

    def __init__(self):
        self._lock = threading.Lock()
        # key -> list of timestamps
        self._windows: dict[str, list[float]] = defaultdict(list)

    def _clean(self, key: str, window_seconds: float):
        """Remove expired entries for a key."""
        cutoff = time.time() - window_seconds
        self._windows[key] = [t for t in self._windows[key] if t > cutoff]

    def is_allowed(self, key: str, max_requests: int, window_seconds: float) -> bool:
        """Check if request is allowed under the rate limit."""
        with self._lock:
            self._clean(key, window_seconds)
            if len(self._windows[key]) >= max_requests:
                return False
            self._windows[key].append(time.time())
            return True

    def reset(self, key: str):
        """Reset the counter for a key (e.g., after successful login)."""
        with self._lock:
            self._windows.pop(key, None)


# Global rate limiters
_login_limiter = RateLimiter()

# Login rate limits
LOGIN_PER_MINUTE = 5
LOGIN_PER_15_MINUTES = 20
LOGIN_WINDOW = 60  # seconds
LOGIN_WINDOW_EXTENDED = 900  # 15 minutes


def check_login_rate_limit(client_ip: str) -> bool:
    """Check if this IP is allowed to attempt login. Returns True if allowed."""
    # Short window: 5 per minute
    if not _login_limiter.is_allowed(f"login_short:{client_ip}", LOGIN_PER_MINUTE, LOGIN_WINDOW):
        return False
    # Extended window: 20 per 15 minutes
    if not _login_limiter.is_allowed(f"login_long:{client_ip}", LOGIN_PER_15_MINUTES, LOGIN_WINDOW_EXTENDED):
        return False
    return True


def clear_login_attempts(client_ip: str):
    """Clear rate limit counters after successful login."""
    _login_limiter.reset(f"login_short:{client_ip}")
    _login_limiter.reset(f"login_long:{client_ip}")


def check_login_exponential_backoff(client_ip: str, consecutive_failures: int) -> float | None:
    """Calculate exponential backoff delay. Returns seconds to wait, or None if no delay."""
    if consecutive_failures < 3:
        return None
    delay = min(2 ** (consecutive_failures - 2), 300)  # Max 5 minutes
    return delay
