"""Security HTTP middleware: headers + global access control."""

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from common.security_config import get_security_config


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security-related HTTP response headers."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)

        headers = {
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "X-Frame-Options": "DENY",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
            "Cache-Control": "no-store",
        }

        # CSP: inline scripts allowed temporarily for legacy panel HTML
        # TODO: extract panel JS to external files and remove 'unsafe-inline'
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "media-src 'self' blob:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'none'; "
            "form-action 'self'; "
            "object-src 'none'"
        )
        headers["Content-Security-Policy"] = csp

        for name, value in headers.items():
            if name not in response.headers:
                response.headers[name] = value

        return response
