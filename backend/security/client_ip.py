"""Client IP resolution with trusted proxy support.

Only trusts X-Forwarded-For from configured proxy CIDRs.
Prevents IP spoofing through untrusted headers.
"""

import ipaddress
from fastapi import Request
from common.security_config import get_security_config


def _is_trusted_proxy(ip: str) -> bool:
    """Check if an IP is in the trusted proxy CIDR list."""
    sec = get_security_config()
    try:
        addr = ipaddress.ip_address(ip)
        for cidr_str in sec.trusted_proxy_cidrs:
            if addr in ipaddress.ip_network(cidr_str):
                return True
    except ValueError:
        return False
    return False


def get_client_ip(request: Request) -> str:
    """Get the real client IP, respecting trusted proxies only.
    
    If the direct peer is a trusted proxy, use the rightmost
    X-Forwarded-For value. Otherwise, use the direct peer address.
    """
    peer_ip = request.client.host if request.client else "127.0.0.1"

    if _is_trusted_proxy(peer_ip):
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            # Rightmost IP is the original client (our app may be behind multiple proxies)
            ips = [ip.strip() for ip in forwarded.split(",")]
            for ip in reversed(ips):
                if ip:
                    try:
                        ipaddress.ip_address(ip)
                        return ip
                    except ValueError:
                        continue

    return peer_ip


def get_client_ip_hash(request: Request) -> str | None:
    """Get a one-way hash of the client IP for audit logging."""
    import hashlib
    ip = get_client_ip(request)
    return hashlib.sha256(f"ip:{ip}".encode()).hexdigest()[:16]
