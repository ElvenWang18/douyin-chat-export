# Security Policy

## Supported Versions

Only the latest release is supported with security updates.

| Version | Supported |
|---------|-----------|
| 2.x     | ✅        |
| 1.x     | ❌        |

## Reporting a Vulnerability

**Do NOT open a public issue for security vulnerabilities.**

Instead:
1. Email the maintainer directly.
2. Provide a clear description of the vulnerability.
3. Include steps to reproduce if possible.
4. Allow up to 5 business days for initial response.

**Never include** in any report:
- Your chat database (chat.db)
- Your browser profile
- Cookie values or session tokens
- Screenshots of your chat messages

## Security Model

This project handles highly sensitive personal data (private chat messages,
cookies, media files). It is designed for **self-hosted personal use** and
should NEVER be exposed directly to the public internet without a reverse
proxy and proper authentication.

### Security Guarantees (v2+)

- Passwords hashed with Argon2id (auto-migrates from SHA-256)
- Session tokens stored as SHA-256 hashes (never in plaintext)
- HttpOnly cookies prevent JavaScript token access
- CSRF protection on all state-changing operations
- Media files require authentication
- Exports auto-expire and support one-time downloads
- Logs are redacted (no cookies, tokens, or UIDs in logs)
- Container runs as non-root with dropped capabilities

### Known Limitations

- Chat messages are stored in plaintext in SQLite (encryption at rest requires LUKS/BitLocker at the host level)
- Web panel uses inline scripts ('unsafe-inline' in CSP — tracked as technical debt)
- No multi-factor authentication
- Rate limiting is in-memory (resets on restart)
- No built-in backup encryption (use host-level encryption)

## Secure Deployment

See [docs/secure-deployment.md](docs/secure-deployment.md) for detailed
deployment guidance at three security levels.

## Incident Response

If you discover your data has been exposed:

1. Immediately stop the container: `docker compose down`
2. Change your Douyin password
3. Revoke your Douyin session
4. Delete any exposed backups or exports
5. Rotate the application secret key
6. Review access logs

## Disclosure Timeline

We aim to:
- Acknowledge reports within 5 business days
- Confirm or reproduce the issue within 10 business days
- Release a fix for critical issues within 30 days
- Publish advisories after fixes are available
