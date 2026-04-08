"""TCP connect scanning helpers built on the standard socket library."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


def scan_port(host: str, port: int, timeout: float = 1.0) -> dict[str, int | str]:
    """Scan a single TCP port and attempt a banner grab when it is open."""

    banner = ""
    state = "closed"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                state = "open"
                try:
                    sock.settimeout(timeout)
                    banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                except Exception:
                    banner = ""
    except Exception:
        state = "closed"
        banner = ""

    return {"port": port, "state": state, "banner": banner}


def scan_range(
    host: str,
    start: int,
    end: int,
    timeout: float,
    threads: int,
) -> list[dict[str, int | str]]:
    """Scan a TCP port range concurrently and return open ports only."""

    ports = list(range(start, end + 1))
    if not ports:
        return []

    max_workers = max(1, min(threads, len(ports)))
    results: list[dict[str, int | str]] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(scan_port, host, port, timeout): port for port in ports
        }
        for future in as_completed(future_map):
            try:
                result = future.result()
            except Exception:
                continue
            if result.get("state") == "open":
                results.append(result)

    results.sort(key=lambda item: int(item["port"]))
    return results