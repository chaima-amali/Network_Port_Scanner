"""SYN scanning helpers built with Scapy."""

from __future__ import annotations

import os

try:
    from scapy.all import IP, TCP, conf, sr1
except ImportError:  # pragma: no cover - fallback for environments without Scapy
    class _DummyPacket:
        """Minimal packet object that supports Scapy-style layering syntax."""

        def __init__(self, **kwargs: object) -> None:
            self.__dict__.update(kwargs)

        def __truediv__(self, other: object) -> "_DummyPacket":
            return self

    class _DummyLayerFactory:
        """Factory that mimics the callable Scapy layer classes."""

        def __call__(self, *args: object, **kwargs: object) -> _DummyPacket:
            return _DummyPacket(**kwargs)

    IP = _DummyLayerFactory()  # type: ignore[assignment]
    TCP = _DummyLayerFactory()  # type: ignore[assignment]

    class _Conf:
        """Minimal configuration shim used when Scapy is unavailable."""

        verb = 0

    conf = _Conf()  # type: ignore[assignment]

    def sr1(*args: object, **kwargs: object) -> None:
        """Fallback sr1 implementation that returns no response."""

        return None


conf.verb = 0


def _has_privileges() -> bool:
    """Return True when the current process appears to have root privileges."""

    geteuid = getattr(os, "geteuid", None)
    if callable(geteuid):
        return geteuid() == 0
    return False


def syn_scan(host: str, port: int) -> str:
    """Perform a single TCP SYN scan probe and classify the port state."""

    try:
        response = sr1(IP(dst=host) / TCP(dport=port, flags="S"), timeout=1, verbose=0)
        if response is None:
            return "filtered"

        flags = int(getattr(response, "flags", 0))
        if flags == 0x12:
            sr1(IP(dst=host) / TCP(dport=port, flags="R"), timeout=0.5, verbose=0)
            return "open"
        if flags == 0x14:
            return "closed"
        return "filtered"
    except Exception:
        return "filtered"


def syn_scan_range(host: str, start: int, end: int) -> list[dict[str, int | str]]:
    """Scan a port range with SYN probes and return open ports only."""

    if not _has_privileges():
        print("Warning: SYN scan usually requires root or administrator privileges.")

    results: list[dict[str, int | str]] = []
    for port in range(start, end + 1):
        try:
            if syn_scan(host, port) == "open":
                results.append({"port": port, "state": "open", "banner": ""})
        except Exception:
            continue

    results.sort(key=lambda item: int(item["port"]))
    return results
