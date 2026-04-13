"""TCP connect scanner — Person A's module.

Uses Python's built-in socket library with ThreadPoolExecutor for
parallel scanning. No root privileges required.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


def grab_banner(sock: socket.socket) -> str:
    """Read the service banner from an already-connected socket."""
    try:
        sock.settimeout(2.0)
        raw = sock.recv(1024)
        return raw.decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""


def scan_port(host: str, port: int, timeout: float = 1.0) -> dict:
    """Probe a single TCP port; return state and banner."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                banner = grab_banner(sock)
                return {"port": port, "state": "open", "banner": banner}
    except Exception:
        pass
    return {"port": port, "state": "closed", "banner": ""}


def scan_range(
    host: str,
    start: int,
    end: int,
    timeout: float = 1.0,
    max_workers: int = 100,
) -> list[dict]:
    """Scan a port range in parallel; return only open ports."""
    open_ports: list[dict] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_port, host, port, timeout): port
            for port in range(start, end + 1)
        }
        for future in as_completed(futures):
            result = future.result()
            if result["state"] == "open":
                open_ports.append(result)

    return sorted(open_ports, key=lambda x: x["port"])
