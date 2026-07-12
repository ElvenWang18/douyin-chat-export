# Security Migration Guide (v1 → v2)

## What Changed

### Authentication
| v1 | v2 |
|----|----|
| SHA-256 password in panel_config.json | Argon2id in data/auth/auth.db |
| Token in localStorage | HttpOnly session cookie |
| Bearer token + ?token= query | __Host-dce_session cookie |
| No CSRF | X-CSRF-Token + Origin check |
| No rate limiting | IP-based login rate limiting |
| Token lasts 7 days | Idle 30min / Absolute 24h / Remember 7d |

### Media Access
| v1 | v2 |
|----|----|
| /media/* public | /api/media/* requires session |
| Path traversal possible | Path resolution + parent check |

### Exports
| v1 | v2 |
|----|----|
| data/export.json (fixed name) | data/exports/<uuid>/payload.{json,jsonl,zip} |
| Permanent | Auto-expires (default 15 min) |
| Unrestricted downloads | One-time download option |
| No metadata | Auth DB tracks all exports |

### Docker
| v1 | v2 |
|----|----|
| root (uid 0) | appuser (uid 10001) |
| All capabilities | ALL dropped |
| -- | no-new-privileges |
| No health check | /healthz endpoint |

### Directory Structure
| v1 | v2 |
|----|----|
| data/chat.db | data/database/chat.db |
| data/scrape.log | data/logs/scrape.log |
| data/panel_config.json | data/panel_config.json (unchanged) |
| — | data/auth/auth.db (new) |
| — | data/exports/ (new) |

## Upgrade Steps

1. **Backup your data**:
   ```bash
   tar czf backup-$(date +%Y%m%d).tar.gz data/
   ```

2. **Pull new image or rebuild**:
   ```bash
   git checkout security-hardening-v1
   docker compose build
   ```

3. **Start with the new version**:
   ```bash
   docker compose up -d
   ```

4. **Path migration happens automatically**:
   - chat.db moves from data/ to data/database/
   - Logs move from data/ to data/logs/

5. **Password migration**:
   - Your old SHA-256 password still works
   - First login auto-upgrades to Argon2id
   - Old hash is removed from panel_config.json

6. **Set strong secret key**:
   ```bash
   # Add to docker-compose.yml environment:
   APP_SECRET_KEY=*** -c "import secrets; print(secrets.token_hex(32))")
   ```

7. **Set APP_ENV to production after verifying**:
   ```env
   APP_ENV=production
   COOKIE_SECURE=true  # Only if behind HTTPS proxy
   ```

## Rollback

1. **Stop the container**:
   ```bash
   docker compose down
   ```

2. **Switch back to main branch**:
   ```bash
   git checkout main
   docker compose build
   ```

3. **Move data back to legacy locations**:
   ```bash
   mv data/database/chat.db data/chat.db
   mv data/logs/scrape.log data/scrape.log
   mv data/logs/discover.log data/discover.log
   ```

4. **Start v1**:
   ```bash
   docker compose up -d
   ```

## Breaking Changes

1. **Frontend** must be rebuilt (media paths changed from /media/ to /api/media/)
2. **Bookmarks** using ?token= no longer work
3. **Direct /media/ links** no longer work without authentication
4. **Export files** at fixed paths are no longer generated (use the panel download)
5. **panel_config.json** password_hash is deprecated (migrated to auth.db)
