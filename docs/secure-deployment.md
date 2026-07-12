# Secure Deployment Guide

Three deployment levels, from most secure to most exposed.

## Level 1: Local Only (Recommended for personal use)

```yaml
# docker-compose.local.yml
services:
  douyin-chat-export:
    # ... standard config ...
    ports:
      - "127.0.0.1:8000:8000"
    environment:
      - APP_ENV=development
```

- Binds only to `127.0.0.1` (loopback)
- No external network access possible
- Access via `http://localhost:8000` on the same machine
- Set password via control panel at first startup

## Level 2: Private Network

```yaml
# docker-compose.private.yml
services:
  douyin-chat-export:
    # ... standard config ...
    ports:
      - "127.0.0.1:8000:8000"
    environment:
      - APP_ENV=production
      - APP_SECRET_KEY=<generate with: openssl rand -hex 32>
```

Access via:
- **Tailscale** / **WireGuard** VPN tunnel
- **SSH tunnel**: `ssh -L 8000:127.0.0.1:8000 your-server`
- **Local reverse proxy** on the same machine

Set admin network to private CIDR:
```env
ADMIN_ALLOWED_CIDRS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.1/32
```

## Level 3: HTTPS Public Gateway

**WARNING**: Only use this if you fully understand the risks.

```yaml
# docker-compose.public.yml
services:
  douyin-chat-export:
    # ... standard config ...
    # NO ports mapping — only reverse proxy talks to it
    networks:
      - web-internal
    environment:
      - APP_ENV=production
      - APP_SECRET_KEY=<random 64-char hex>
      - COOKIE_SECURE=true
      - ENABLE_REMOTE_LOGIN=false
      - ENABLE_COOKIE_IMPORT=false
      - TRUSTED_PROXY_CIDRS=10.0.0.0/8,172.16.0.0/12
```

### Caddy reverse proxy example:

```caddyfile
chat.example.com {
    reverse_proxy douyin-chat-export:8000
    header {
        X-Forwarded-Proto https
        X-Forwarded-For {remote_host}
    }
    # Optional: add basic auth as defense-in-depth
    # basicauth {
    #     $2a$14$...
    # }
}
```

### Nginx reverse proxy example:

```nginx
server {
    listen 443 ssl;
    server_name chat.example.com;

    ssl_certificate /etc/ssl/certs/chat.pem;
    ssl_certificate_key /etc/ssl/private/chat.key;

    location / {
        proxy_pass http://douyin-chat-export:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

## NEVER do this

```yaml
# DO NOT DO THIS — your data WILL leak
ports:
  - "8000:8000"  # Exposes to 0.0.0.0 on ALL interfaces
```

```yaml
# DO NOT DO THIS — bypasses all authentication
environment:
  - ALLOW_INSECURE_NO_PASSWORD=true
```

## Password Setup

On first startup:

1. Access the control panel at `/panel`
2. Click "设置密码" in the sidebar
3. Enter a strong password (16+ characters recommended)

Or set via CLI:
```bash
docker exec douyin-chat-export python -m backend.cli set-password
```

## Verification

After deployment, verify these security properties:

```bash
# 1. Health check works without auth
curl http://127.0.0.1:8000/healthz
# → {"status":"ok"}

# 2. API requires authentication
curl http://127.0.0.1:8000/api/stats
# → 401 {"detail":"Not authenticated"}

# 3. Media requires authentication
curl http://127.0.0.1:8000/api/media/any
# → 401 {"detail":"Not authenticated"}

# 4. Container runs as non-root
docker exec douyin-chat-export id
# → uid=10001(appuser) gid=10001(appuser)

# 5. No token in localStorage (check browser DevTools)
# → Application → Local Storage → no authToken key
```
