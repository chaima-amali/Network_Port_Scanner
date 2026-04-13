"""UDP port scanner — Person A's module.

Sends empty UDP datagrams and listens for ICMP port-unreachable
responses to infer port state. Requires root on Linux/macOS.
"""

from __future__ import annotations

import socket


def udp_scan(host: str, port: int, timeout: float = 2.0) -> dict:
    """Probe a single UDP port.

    Returns:
        dict with keys: port, state ('open|filtered' or 'closed')
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(b"", (host, port))
            try:
                sock.recvfrom(1024)
                return {"port": port, "state": "open|filtered"}
            except socket.timeout:
                # No ICMP unreachable received within timeout → likely open/filtered
                return {"port": port, "state": "open|filtered"}
    except ConnectionRefusedError:
        # ICMP port unreachable → closed
        return {"port": port, "state": "closed"}
    except PermissionError:
        return {"port": port, "state": "error: requires root"}
    except Exception:
        return {"port": port, "state": "error"}


def udp_scan_range(host: str, ports: list[int], timeout: float = 2.0) -> list[dict]:
    """Scan a list of UDP ports sequentially."""
    return [udp_scan(host, port, timeout) for port in ports]
