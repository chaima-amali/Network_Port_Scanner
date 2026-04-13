"""Banner grabbing module — Person B's module.

Connects to an open port and reads the first bytes the service sends,
revealing software name and version (e.g. "SSH-2.0-OpenSSH_9.1").
"""

from __future__ import annotations

import socket

# Common services that require us to send a probe before they respond
_HTTP_PROBE = b"HEAD / HTTP/1.0\r\n\r\n"

# Ports that speak HTTP and need a probe to return a banner
_HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888}


def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    """Connect to *host*:*port* and return the service banner string.

    For HTTP ports a minimal HEAD request is sent first so the server
    returns its response headers (which include the Server: header).

    Args:
        host:    Target IP address or hostname.
        port:    TCP port number.
        timeout: Socket timeout in seconds.

    Returns:
        Decoded banner string, or empty string if nothing was received.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))

            # Some services (HTTP) won't send anything until we speak first
            if port in _HTTP_PORTS:
                sock.sendall(_HTTP_PROBE)

            raw = sock.recv(1024)
            return raw.decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""


def enrich_with_banners(open_ports: list[dict], host: str, timeout: float = 2.0) -> list[dict]:
    """Add banner information to a list of open-port dicts from the scanner.

    The scanner's grab_banner reads from an already-connected socket,
    which sometimes misses banners that need a fresh connection.
    This function re-connects specifically for banner grabbing.

    Args:
        open_ports: List of dicts with at least {"port": int, "state": str}.
        host:       Target host.
        timeout:    Socket timeout per port.

    Returns:
        Same list with "banner" key populated (existing values preserved
        if already non-empty).
    """
    enriched = []
    for entry in open_ports:
        port = entry["port"]
        # Only re-grab if banner is missing
        banner = entry.get("banner") or grab_banner(host, port, timeout)
        enriched.append({**entry, "banner": banner})
    return enriched


# ── Convenience: parse a banner into a service label ────────────────────────

_BANNER_SIGNATURES: list[tuple[str, str]] = [
    ("SSH-",          "SSH"),
    ("220",           "FTP/SMTP"),
    ("HTTP/",         "HTTP"),
    ("220-",          "FTP"),
    ("+OK",           "POP3"),
    ("* OK",          "IMAP"),
    ("220 ",          "SMTP"),
    ("RFB ",          "VNC"),
    ("SMB",           "SMB"),
]


def identify_service(banner: str) -> str:
    """Best-effort service identification from a banner string.

    Args:
        banner: Raw banner text.

    Returns:
        Human-readable service label or 'Unknown'.
    """
    if not banner:
        return "Unknown"
    upper = banner.upper()
    for signature, label in _BANNER_SIGNATURES:
        if upper.startswith(signature.upper()):
            return label
    return "Unknown"
