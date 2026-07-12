"""CSRF protection for state-changing requests.

All POST/PUT/PATCH/DELETE requests must include either:
- X-CSRF-Token header matching the session's CSRF hash
- Or pass the validate_csrf check
"""

from fastapi import Request, HTTPException

from .sessions import validate_session_token, validate_csrf_token


async def csrf_protection(request: Request) -> None:
    """Verify CSRF token for state-changing requests.
    
    Must be called after session validation.
    The session token is read from the cookie.
    """
    # Skip CSRF for GET/HEAD/OPTIONS
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return

    session_cookie_name = "dce_session_dev"
    try:
        from .sessions import get_session_cookie_name
        session_cookie_name = get_session_cookie_name()
    except Exception:
        pass

    session_token = request.cookies.get(session_cookie_name, "")
    if not session_token:
        raise HTTPException(401, "Not authenticated")

    session = validate_session_token(session_token)
    if not session:
        raise HTTPException(401, "Session expired")

    csrf_token = request.headers.get("X-CSRF-Token", "")
    if not csrf_token:
        raise HTTPException(403, "Missing CSRF token")

    if not validate_csrf_token(session, csrf_token):
        raise HTTPException(403, "Invalid CSRF token")


async def origin_validation(request: Request) -> None:
    """Validate Origin/Referer headers match the expected host."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return

    origin = request.headers.get("Origin", "")
    host = request.headers.get("Host", "")
    
    if not origin:
        # No Origin header on non-browser request. Check for Referer.
        referer = request.headers.get("Referer", "")
        if not referer:
            # Some API clients don't send either - allow in dev, warn in prod
            return
        # Parse referer to check host
        try:
            from urllib.parse import urlparse
            parsed = urlparse(referer)
            if parsed.hostname and parsed.hostname != host and not host.startswith("localhost"):
                raise HTTPException(403, "Cross-origin request blocked")
        except HTTPException:
            raise
        except Exception:
            pass
        return

    # Browser request with Origin
    try:
        from urllib.parse import urlparse
        parsed = urlparse(origin)
        if parsed.hostname and parsed.hostname != host:
            raise HTTPException(403, "Cross-origin request blocked")
    except HTTPException:
        raise
    except Exception:
        pass
