"""Server酱 (sct.ftqq.com) failure notifications for the control panel.

Security-v2: No longer sends raw log tail contents.
Only sends timestamp, error category, exit code, request_id, and local log path.
"""

import asyncio
import json
import os
import time

from common import config


def send_serverchan_sync(sendkey: str, title: str, desp: str) -> tuple[bool, str]:
    """Blocking POST to Server酱. Returns (ok, message)."""
    import urllib.request
    import urllib.parse

    url = f"https://sctapi.ftqq.com/{sendkey}.send"
    data = urllib.parse.urlencode({"title": title, "desp": desp}).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            try:
                payload = json.loads(body)
                code = payload.get("code", payload.get("errno", -1))
                if code == 0:
                    return True, "已发送"
                return False, f"Server酱返回错误: {payload.get('message') or body[:200]}"
            except json.JSONDecodeError:
                return False, f"Server酱响应非 JSON: {body[:200]}"
    except Exception as e:
        return False, f"请求失败: {e}"


def build_failure_desp(reason: str, log_path: str | None = None) -> str:
    """Build a privacy-safe notification body for failure notifications.
    
    Security: does NOT include log tail content.
    Only includes: timestamp, error reason, and log file location.
    """
    import datetime
    import hashlib
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    request_id = hashlib.sha256(f"{ts}:{reason}".encode()).hexdigest()[:12]

    parts = [
        f"**失败时间**: {ts}",
        f"**原因**: {reason or '未知错误'}",
        f"**追踪 ID**: req-{request_id}",
    ]
    if log_path and os.path.exists(log_path):
        parts.append(f"**日志位置**: 容器内 `{log_path}`")
    else:
        parts.append("**日志位置**: 查看控制面板日志")

    return "\n\n".join(parts)


async def notify_on_failure(title: str, desp: str) -> None:
    """Fire-and-forget notification. Reads sendkey from config; silently no-ops if not set.
    
    Respects ENABLE_SERVERCHAN flag from security config.
    """
    try:
        from common.security_config import get_security_config
        sec = get_security_config()
        if not sec.enable_serverchan:
            return
    except Exception:
        pass

    cfg = config.load_config()
    sendkey = (cfg.get("notify_serverchan_key") or "").strip()
    if not sendkey:
        return
    try:
        ok, msg = await asyncio.to_thread(send_serverchan_sync, sendkey, title, desp)
        if not ok:
            print(f"[!] 通知发送失败: {msg}")
    except Exception as e:
        print(f"[!] 通知发送异常: {e}")
