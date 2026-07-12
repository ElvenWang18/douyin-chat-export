"""FastAPI dependency injection for authorization.

Provides reusable dependencies that routes can declare.
"""

from fastapi import Request, HTTPException, Depends

from .sessions import validate_session_token
from .csrf import csrf_protection, origin_validation
from .client_ip import get_client_ip
from common.security_config import get_security_config


async def require_session(request: Request) -> dict:
    """Dependency: require a valid authenticated session.
    
    Returns the session dict if valid, raises 401 otherwise.
    """
    # Determine cookie name
    sec = get_security_config()
    if sec.is_production():
        cookie_name = "__Host-dce_session"
    else:
        cookie_name = "dce_session_dev"

    session_token = request.cookies.get(cookie_name, "")
    if not session_token:
        # Also check Authorization header (backward compat during migration)
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            session_token = auth.removeprefix("Bearer ").strip()

    if not session_token:
        raise HTTPException(401, "Not authenticated")

    session = validate_session_token(session_token)
    if not session:
        raise HTTPException(401, "Session expired or invalid")

    return session


async def require_admin_network(request: Request) -> None:
    """Dependency: verify request comes from admin-allowed network."""
    sec = get_security_config()
    client_ip = get_client_ip(request)

    import ipaddress
    try:
        addr = ipaddress.ip_address(client_ip)
        for cidr_str in sec.admin_allowed_cidrs:
            if addr in ipaddress.ip_network(cidr_str):
                return
    except ValueError:
        pass

    raise HTTPException(403, "Admin access requires trusted network")


async def require_recent_auth(session: dict = Depends(require_session)) -> None:
    """Dependency: require password re-authentication within the last 5 minutes."""
    import time
    elevated_until = session.get("elevated_until", 0)
    if not elevated_until or int(time.time()) > elevated_until:
        raise HTTPException(
            403,
            "This operation requires recent re-authentication. "
            "Please re-enter your password."
        )


async def require_csrf(request: Request) -> None:
    """Dependency: require valid CSRF token for state-changing requests."""
    await csrf_protection(request)
    await origin_validation(request)
