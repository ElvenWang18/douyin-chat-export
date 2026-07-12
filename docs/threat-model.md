# Threat Model

## Assets (by sensitivity)

### S0 — Account Credentials
- Douyin `sessionid` and other cookies
- `data/browser_profile/` (Chromium persistent login state)
- Admin password hash
- Session tokens
- Server酱 SendKey

### S1 — Chat Content
- Private messages, group messages
- Referenced messages (ref_msg)
- Voice recordings, images, videos
- Raw API response data (raw_data column)
- Export files

### S2 — Identity Information
- Douyin UIDs (user IDs)
- Nicknames, unique IDs
- Avatar URLs
- Conversation names
- Group member lists

### S3 — Operational Metadata
- Scrape timestamps
- Task status
- Logs
- Export history

## Attack Scenarios

| # | Scenario | Severity | Mitigation (v2) |
|---|----------|----------|------------------|
| 1 | Port accidentally exposed to internet without password | Critical | Fail-closed startup check |
| 2 | Weak password brute-forced | High | Argon2id + rate limiting |
| 3 | Database file copied from host | High | Separate auth.db; passwords always hashed |
| 4 | XSS steals token from localStorage | High | HttpOnly cookies only |
| 5 | Direct media URL access without login | High | Protected /api/media/ routing |
| 6 | Export file left on disk indefinitely | Medium | Auto-expiry + one-time download |
| 7 | Logs contain cookies/UIDs/messages | Medium | Redaction patterns applied |
| 8 | Server酱 sends raw logs to third party | Medium | Privacy-safe notification format |
| 9 | Container escape via root access | Medium | Non-root user + no-new-privileges |
| 10 | CSRF triggers delete/export | Medium | X-CSRF-Token + Origin validation |
| 11 | Path traversal reads chat.db via /media | High | Path resolution + parent check |
| 12 | Supply chain compromise via deps | Medium | Locked versions + Dependabot + CI scans |

## Non-Goals

The following are explicitly out of scope:
- Multi-tenancy (designed for single user)
- Defense against attacker with root on the host
- Full-disk encryption at application level
- Protecting files after user downloads and re-uploads them
- Rewriting Douyin protocol or scraping engine

## Trust Boundaries

```
User's Browser
    │ HTTPS / SSH tunnel / localhost
    ▼
Reverse Proxy (Caddy/Nginx)
    │ Optional: external auth, TSL, rate limiting
    ▼
FastAPI Application
    │ Session-based auth (HttpOnly cookie)
    │ CSRF validation on mutations
    │ Admin network restrictions
    │     ├── Viewer API (Authenticated)
    │     └── Admin API (Authenticated + Admin Network)
    │
    ├── chat.db (chat messages)
    ├── auth.db (credentials, sessions, audit)
    ├── browser_profile/ (d...state)
    ├── media/ (images, voice, video — protected)
    ├── exports/ (UUID-named, auto-expiring)
    └── logs/ (redacted structured logs)
```
