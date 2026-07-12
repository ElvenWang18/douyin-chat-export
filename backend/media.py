"""Protected media routing — replaces the insecure StaticFiles mount.

All media access requires session authentication.
Path traversal is prevented via path resolution checks.
"""

import os
import mimetypes
from pathlib import Path

from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.responses import FileResponse, StreamingResponse

from common import paths
from backend.security.dependencies import require_session

router = APIRouter(tags=["media"])

# Allowed MIME types
_ALLOWED_MIME_TYPES = {
    "image/jpeg", "image/png", "image/webp", "image/gif",
    "audio/mpeg", "audio/wav", "audio/ogg",
    "video/mp4", "video/webm",
    "application/octet-stream",  # for downloads, inline=False
}

# MIME types that should never be served inline
_BLOCKED_MIME_TYPES = {
    "text/html", "image/svg+xml", "application/javascript",
    "application/x-javascript", "text/javascript",
}


def _resolve_media_path(relative_path: str) -> Path:
    """Resolve a relative path to an absolute path within MEDIA_DIR.
    
    Raises HTTPException if path traversal or other abuse is detected.
    """
    # Decode URL
    import urllib.parse
    decoded = urllib.parse.unquote(relative_path)

    # Normalize
    media_root = Path(paths.MEDIA_DIR).resolve()
    candidate = (media_root / decoded).resolve()

    # Must still be under MEDIA_DIR
    try:
        candidate.relative_to(media_root)
    except ValueError:
        raise HTTPException(404, "Not found")

    # Must be a regular file
    if not candidate.is_file():
        raise HTTPException(404, "Not found")

    # No symlinks (unless they resolve within MEDIA_DIR)
    if candidate.is_symlink():
        raise HTTPException(404, "Not found")

    return candidate


def _get_mime_type(file_path: Path) -> str:
    """Determine MIME type, defaulting to application/octet-stream."""
    mime, _ = mimetypes.guess_type(str(file_path))
    return mime or "application/octet-stream"


def _security_headers(file_path: Path, mime_type: str) -> dict:
    """Build security headers for media response."""
    headers = {
        "Cache-Control": "private, no-store",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'",
    }
    return headers


@router.get("/api/media/{rest_of_path:path}")
async def serve_media(
    rest_of_path: str,
    request: Request,
    session: dict = Depends(require_session),
):
    """Serve a protected media file.
    
    Path is validated, MIME type is checked, and security headers are set.
    """
    file_path = _resolve_media_path(rest_of_path)
    mime_type = _get_mime_type(file_path)

    # Block dangerous MIME types
    if mime_type in _BLOCKED_MIME_TYPES:
        raise HTTPException(415, "Unsupported media type")

    if mime_type not in _ALLOWED_MIME_TYPES:
        # Unknown types: only allow as download
        mime_type = "application/octet-stream"

    headers = _security_headers(file_path, mime_type)

    # For video/audio, support Range requests
    if mime_type.startswith("video/") or mime_type.startswith("audio/"):
        return FileResponse(
            str(file_path),
            media_type=mime_type,
            headers=headers,
            filename=file_path.name,
        )

    return FileResponse(
        str(file_path),
        media_type=mime_type,
        headers=headers,
        filename=file_path.name,
    )
