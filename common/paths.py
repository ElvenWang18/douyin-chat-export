"""Single source of truth for every filesystem path in the project.

All state lives under DATA_DIR, which is the single bind-mount in Docker
(./data:/app/data) and is git-ignored.

Security update (v2): Directory structure now separates concerns:
  data/
    auth/          — auth.db (credentials, sessions, audit)
    database/      — chat.db
    browser_profile/ — Chromium persistent state
    media/         — images, voice, video, avatars, emoji
    exports/       — generated export payloads
    logs/          — scrape.log, discover.log
    panel_config.json — panel settings
"""

import os
import shutil

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(REPO_ROOT, "data")

# ── Sub-directories ────────────────────────────────────────────
AUTH_DIR = os.path.join(DATA_DIR, "auth")
DATABASE_DIR = os.path.join(DATA_DIR, "database")
BROWSER_PROFILE = os.path.join(DATA_DIR, "browser_profile")
MEDIA_DIR = os.path.join(DATA_DIR, "media")
EXPORT_DIR = os.path.join(DATA_DIR, "exports")
LOG_DIR = os.path.join(DATA_DIR, "logs")
CONFIG_DIR = DATA_DIR

# ── Databases ──────────────────────────────────────────────────
AUTH_DB_PATH = os.path.join(AUTH_DIR, "auth.db")
DB_PATH = os.path.join(DATABASE_DIR, "chat.db")
CONFIG_PATH = os.path.join(DATA_DIR, "panel_config.json")

# ── Logs ───────────────────────────────────────────────────────
SCRAPE_LOG = os.path.join(LOG_DIR, "scrape.log")
DISCOVER_LOG = os.path.join(LOG_DIR, "discover.log")
CONVERSATIONS_LIST = os.path.join(LOG_DIR, "conversations_list.json")

# ── Media subdirectories ───────────────────────────────────────
IMAGES_DIR = os.path.join(MEDIA_DIR, "images")
EMOJI_DIR = os.path.join(MEDIA_DIR, "emoji")
VOICE_DIR = os.path.join(MEDIA_DIR, "voice")
AVATARS_DIR = os.path.join(MEDIA_DIR, "avatars")
VIDEOS_DIR = os.path.join(MEDIA_DIR, "videos")

# ── Frontend build output ──────────────────────────────────────
FRONTEND_DIST = os.path.join(REPO_ROOT, "frontend", "dist")

# ── Legacy paths (pre-v2 structure) ────────────────────────────
LEGACY_DB_PATH = os.path.join(DATA_DIR, "chat.db")
LEGACY_SCRAPE_LOG = os.path.join(DATA_DIR, "scrape.log")
LEGACY_DISCOVER_LOG = os.path.join(DATA_DIR, "discover.log")
LEGACY_CONVERSATIONS_LIST = os.path.join(DATA_DIR, "conversations_list.json")


def migrate_legacy_paths():
    """Migrate files from legacy data/ root to new subdirectories.
    Returns list of migration messages.
    """
    messages = []
    migrations = [
        (LEGACY_DB_PATH, DB_PATH, "chat.db"),
        (LEGACY_SCRAPE_LOG, SCRAPE_LOG, "scrape.log"),
        (LEGACY_DISCOVER_LOG, DISCOVER_LOG, "discover.log"),
        (LEGACY_CONVERSATIONS_LIST, CONVERSATIONS_LIST, "conversations_list.json"),
    ]

    for legacy, new, name in migrations:
        if not os.path.exists(legacy):
            continue
        if os.path.exists(new):
            messages.append(
                f"Migration skipped: {name} already exists at new path; "
                f"legacy at {legacy} not touched"
            )
            continue

        os.makedirs(os.path.dirname(new), exist_ok=True)
        try:
            os.rename(legacy, new)
            messages.append(f"Migrated: {legacy} -> {new}")
        except OSError:
            try:
                shutil.copy2(legacy, new)
                os.remove(legacy)
                messages.append(f"Migrated (copy): {legacy} -> {new}")
            except OSError as e:
                messages.append(f"Migration failed for {legacy}: {e}")

    return messages
