"""UDP scanning helpers built with Scapy."""

from __future__ import annotations

try:
    from scapy.all import ICMP, IP, UDP, conf, sr1
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

    ICMP = IP = UDP = _DummyLayerFactory()  # type: ignore[assignment]

    class _Conf:
        """Minimal configuration shim used when Scapy is unavailable."""

        verb = 0

    conf = _Conf()  # type: ignore[assignment]

    def sr1(*args: object, **kwargs: object) -> None:
        """Fallback sr1 implementation that returns no response."""

        return None


conf.verb = 0


def udp_scan(host: str, port: int, timeout: float = 2.0) -> dict[str, int | str]:
    """Probe a UDP port and classify it using ICMP port-unreachable replies."""

    state = "open|filtered"

    try:
        response = sr1(IP(dst=host) / UDP(dport=port), timeout=timeout, verbose=0)
        if response is not None:
            icmp_layer = getattr(response, "getlayer", lambda *_: None)(ICMP)
            if icmp_layer is not None:
                icmp_type = int(getattr(icmp_layer, "type", -1))
                icmp_code = int(getattr(icmp_layer, "code", -1))
                if icmp_type == 3 and icmp_code == 3:
                    state = "closed"
    except Exception:
        state = "open|filtered"

    return {"port": port, "state": state}


def udp_scan_range(host: str, ports: list[int]) -> list[dict[str, int | str]]:
    """Scan a list of UDP ports and return the collected results."""

    results: list[dict[str, int | str]] = []
    for port in ports:
        try:
            results.append(udp_scan(host, port))
        except Exception:
            results.append({"port": port, "state": "open|filtered"})

    results.sort(key=lambda item: int(item["port"]))
    return results