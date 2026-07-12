"""FastAPI backend for browsing exported Douyin chat data.

Security-v2: Session-based auth with HttpOnly cookies, Argon2id passwords,
CSRF protection, secure media routing, admin network restrictions.
"""

import asyncio
import json
import os
import time
import uuid

from fastapi import FastAPI, Query, Request, HTTPException, Depends, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import database
from common import config as _cfg, paths
from common.security_config import init_security_config, get_security_config
from common.file_permissions import set_restrictive_umask, initialize_all_permissions
from backend.security.startup_checks import run_startup_checks
from backend.security.sessions import (
    create_session, validate_session_token, refresh_session,
    revoke_session, revoke_all_other_sessions,
    get_session_cookie_name, make_session_cookie, clear_session_cookie,
)
from backend.security.passwords import verify_and_migrate, hash_password, hash_sha256
from backend.security.auth_db import (
    get_stored_password_hash, set_stored_password_hash, clear_stored_password,
)
from backend.security.rate_limit import check_login_rate_limit, clear_login_attempts
from backend.security.client_ip import get_client_ip, get_client_ip_hash
from backend.security.audit import log_audit
from backend.security.middleware import SecurityHeadersMiddleware
from backend.security.dependencies import (
    require_session, require_admin_network, require_recent_auth, require_csrf,
)

# ── App creation ──────────────────────────────────────────────

app = FastAPI(title="抖音聊天记录浏览器", version="2.0.0")

# Security headers middleware
app.add_middleware(SecurityHeadersMiddleware)

# No CORS middleware — same-origin only in production
sec = init_security_config()
if sec.is_development():
    from fastapi.middleware.cors import CORSMiddleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "X-CSRF-Token"],
        allow_credentials=True,
    )


# ── Pydantic models ───────────────────────────────────────────

class AuthLoginRequest(BaseModel):
    password: str
    remember: bool = False


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str


class ReauthRequest(BaseModel):
    password: str


# ── Auth helpers ──────────────────────────────────────────────

def _has_password_set() -> bool:
    """Check if any password is configured (legacy or new)."""
    return bool(get_stored_password_hash() or _cfg.get_password_hash())


def _get_session_token(request: Request) -> str:
    """Extract session token from cookie or Authorization header."""
    cookie_name = get_session_cookie_name()
    token = request.cookies.get(cookie_name, "")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth.removeprefix("Bearer ").strip()
    return token


# ── Auth routes ───────────────────────────────────────────────

@app.get("/api/auth/session")
async def auth_session(request: Request):
    """Return current session state and CSRF token."""
    token = _get_session_token(request)
    session = validate_session_token(token) if token else None

    if not session:
        return {
            "authenticated": False,
            "csrf_token": None,
            "recently_authenticated": False,
            "session_expires_at": 0,
        }

    from backend.security.sessions import generate_csrf_token, _hash_token
    from backend.security.auth_db import get_auth_db
    # Rotate CSRF token on each session check
    new_csrf = generate_csrf_token()
    conn = get_auth_db()
    conn.execute(
        "UPDATE sessions SET csrf_hash = ? WHERE id = ?",
        (_hash_token(new_csrf), session["id"]),
    )
    conn.commit()
    conn.close()

    elevated = bool(session.get("elevated_until", 0) and session["elevated_until"] > int(time.time()))
    return {
        "authenticated": True,
        "csrf_token": new_csrf,
        "recently_authenticated": elevated,
        "session_expires_at": session["absolute_expires_at"],
    }


@app.post("/api/auth/login")
async def auth_login(req: AuthLoginRequest, request: Request, response: Response):
    """Login with password. Sets HttpOnly session cookie."""
    client_ip = get_client_ip(request)

    # Rate limit check
    if not check_login_rate_limit(client_ip):
        raise HTTPException(429, "Too many login attempts. Please wait.")

    if not _has_password_set():
        raise HTTPException(400, "No password configured")

    # Try new auth DB first, then legacy config
    stored_hash = get_stored_password_hash()
    is_legacy = False

    if not stored_hash:
        # Legacy: read from panel_config.json
        legacy_hash = _cfg.get_password_hash()
        if legacy_hash:
            stored_hash = legacy_hash
            is_legacy = True
        else:
            raise HTTPException(400, "No password configured")

    # Verify password
    ok, new_hash = verify_and_migrate(req.password, stored_hash)
    if not ok:
        log_audit("LOGIN_FAILED", "failure", client_ip_hash=get_client_ip_hash(request))
        raise HTTPException(401, "Incorrect password")

    # Migrate legacy SHA-256 to Argon2id
    if new_hash:
        set_stored_password_hash(new_hash)
        # Remove from legacy config
        cfg = _cfg.load_config()
        cfg.pop("password_hash", None)
        _cfg.save_config(cfg)
        log_audit("PASSWORD_HASH_UPGRADED")

    clear_login_attempts(client_ip)

    # Create session
    session_id, session_token, csrf_token = create_session(
        client_ip=get_client_ip_hash(request),
        user_agent=request.headers.get("User-Agent", ""),
        remember=req.remember,
    )

    # Set cookie
    cookie_params = make_session_cookie(
        session_token,
        max_age=sec.session_remember_ttl_seconds if req.remember else sec.session_absolute_ttl_seconds,
    )
    response.set_cookie(**cookie_params)

    log_audit("LOGIN_SUCCESS", actor=session_id, client_ip_hash=get_client_ip_hash(request))

    return {
        "authenticated": True,
        "csrf_token": csrf_token,
    }


@app.post("/api/auth/logout")
async def auth_logout(request: Request, response: Response):
    """Logout: revoke session and clear cookie."""
    token = _get_session_token(request)
    if token:
        revoke_session(token)

    cookie_params = clear_session_cookie()
    response.set_cookie(**cookie_params)
    return {"status": "ok"}


@app.post("/api/auth/reauth")
async def auth_reauth(
    req: ReauthRequest,
    request: Request,
    session: dict = Depends(require_session),
):
    """Re-authenticate for sensitive operations."""
    stored_hash = get_stored_password_hash()
    if not stored_hash:
        raise HTTPException(400, "No password configured")

    ok, _ = verify_and_migrate(req.password, stored_hash)
    if not ok:
        raise HTTPException(403, "Incorrect password")

    # Set elevated_until (5 minutes)
    import time
    from backend.security.auth_db import get_auth_db
    elevated = int(time.time()) + 300
    conn = get_auth_db()
    conn.execute(
        "UPDATE sessions SET elevated_until = ? WHERE id = ?",
        (elevated, session["id"]),
    )
    conn.commit()
    conn.close()

    log_audit("REAUTH_SUCCESS", actor=session["id"])
    return {"status": "ok", "elevated_until": elevated}


@app.post("/api/auth/password")
async def auth_change_password(
    req: PasswordChangeRequest,
    request: Request,
    session: dict = Depends(require_session),
):
    """Change admin password. Requires recent re-auth."""
    import time
    elevated = session.get("elevated_until", 0)
    if not elevated or int(time.time()) > elevated:
        raise HTTPException(403, "Recent re-authentication required")

    stored_hash = get_stored_password_hash()
    if not stored_hash:
        raise HTTPException(400, "No current password")

    ok, _ = verify_and_migrate(req.current_password, stored_hash)
    if not ok:
        raise HTTPException(403, "Current password incorrect")

    # Set new password
    new_hash = hash_password(req.new_password)
    set_stored_password_hash(new_hash)

    # Revoke all other sessions
    revoke_all_other_sessions(session["id"])

    log_audit("PASSWORD_CHANGED", actor=session["id"])
    return {"status": "ok"}


# ── Health check ──────────────────────────────────────────────

@app.get("/healthz")
def healthz():
    """Health check — no sensitive info."""
    return {"status": "ok"}


# ── Protected media routing ──────────────────────────────────

from backend.media import router as media_router
app.include_router(media_router)


# ── Protected API routes ──────────────────────────────────────

@app.get("/api/stats")
async def stats(session: dict = Depends(require_session)):
    return database.get_stats()


@app.get("/api/conversations")
async def list_conversations(
    search: str = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    session: dict = Depends(require_session),
):
    items, total = database.get_conversations(search=search, page=page, page_size=page_size)
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@app.get("/api/conversations/{conv_id}")
async def get_conversation(conv_id: str, session: dict = Depends(require_session)):
    conv = database.get_conversation(conv_id)
    if not conv:
        raise HTTPException(404, "会话不存在")
    return conv


def _do_delete_conversation(conv_id: str):
    conv = database.get_conversation(conv_id)
    if not conv:
        raise HTTPException(404, "会话不存在")
    return database.delete_conversation(conv_id)


@app.delete("/api/conversations/{conv_id}")
async def delete_conversation(
    conv_id: str,
    session: dict = Depends(require_session),
    _csrf=Depends(require_csrf),
):
    log_audit("CONVERSATION_DELETED", actor=session["id"], target_type="conversation")
    return _do_delete_conversation(conv_id)


@app.post("/api/conversations/{conv_id}/delete")
async def delete_conversation_post(
    conv_id: str,
    session: dict = Depends(require_session),
    _csrf=Depends(require_csrf),
):
    log_audit("CONVERSATION_DELETED", actor=session["id"], target_type="conversation")
    return _do_delete_conversation(conv_id)


@app.get("/api/conversations/{conv_id}/messages")
async def list_messages(
    conv_id: str,
    page_size: int = Query(100, ge=1, le=500),
    before_seq: int = Query(None),
    after_seq: int = Query(None),
    session: dict = Depends(require_session),
):
    conv = database.get_conversation(conv_id)
    if not conv:
        raise HTTPException(404, "会话不存在")
    items, total = database.get_messages(conv_id, page_size=page_size, before_seq=before_seq, after_seq=after_seq)
    return {"items": items, "total": total}


@app.get("/api/conversations/{conv_id}/senders")
async def list_senders(conv_id: str, session: dict = Depends(require_session)):
    conv = database.get_conversation(conv_id)
    if not conv:
        raise HTTPException(404, "会话不存在")
    return database.get_senders(conv_id)


@app.get("/api/search")
async def search(
    q: str = Query(..., min_length=1),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    session: dict = Depends(require_session),
):
    items, total = database.search_messages(q, page=page, page_size=page_size)
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@app.get("/api/messages/{msg_id}")
async def get_message(msg_id: str, session: dict = Depends(require_session)):
    msg = database.get_message(msg_id)
    if not msg:
        raise HTTPException(404, "消息不存在")
    return msg


@app.get("/api/users")
async def list_users(session: dict = Depends(require_session)):
    return database.get_all_users()


@app.get("/api/users/{uid}")
async def get_user(uid: str, session: dict = Depends(require_session)):
    user = database.get_user(uid)
    if not user:
        raise HTTPException(404, "用户不存在")
    return user


# ── Control panel (admin routes) ─────────────────────────────

from backend.control_panel import control_router, restore_schedule_on_startup
app.include_router(control_router)


@app.on_event("startup")
async def startup():
    set_restrictive_umask()

    # Migrate legacy paths
    msgs = paths.migrate_legacy_paths()
    for m in msgs:
        print(f"[startup] {m}")

    # Initialize permissions
    initialize_all_permissions()

    # Security startup checks
    try:
        run_startup_checks(sec)
    except Exception as e:
        print(f"[FATAL] {e}")
        if sec.is_production():
            raise
        print("[WARNING] Continuing in development mode despite failed checks")

    # Restore scheduler
    await restore_schedule_on_startup()


# ── Serve Vue frontend (must be last) ────────────────────────

_frontend_dist = paths.FRONTEND_DIST
if os.path.isdir(_frontend_dist):
    app.mount("/assets", StaticFiles(directory=os.path.join(_frontend_dist, "assets")), name="assets")

    _index_html = os.path.join(_frontend_dist, "index.html")

    @app.get("/favicon.svg")
    async def serve_favicon():
        return FileResponse(os.path.join(_frontend_dist, "favicon.svg"), media_type="image/svg+xml")

    @app.get("/")
    async def serve_frontend_root():
        return FileResponse(_index_html)

    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        if full_path.startswith("panel"):
            raise HTTPException(404)
        return FileResponse(_index_html)
