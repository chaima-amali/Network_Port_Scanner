"""SYN (half-open) scanner — Person A's module.

Requires root / Administrator privileges.
Uses Scapy to craft raw IP/TCP SYN packets and read responses
without completing the three-way handshake.
"""

from __future__ import annotations


def syn_scan(host: str, port: int) -> str:
    """Send a SYN packet and return 'open', 'closed', or 'filtered'."""
    try:
        from scapy.all import IP, TCP, conf, sr1  # type: ignore

        conf.verb = 0
        pkt = IP(dst=host) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=1)

        if resp is None:
            return "filtered"

        if resp.haslayer(TCP):
            flags = resp.getlayer(TCP).flags
            if flags == 0x12:  # SYN-ACK → open
                # Send RST to avoid leaving half-open connections
                sr1(IP(dst=host) / TCP(dport=port, flags="R"), timeout=1)
                return "open"
            if flags == 0x14:  # RST-ACK → closed
                return "closed"

        return "filtered"
    except ImportError:
        raise RuntimeError("Scapy is required for SYN scan: pip install scapy")


def syn_scan_range(host: str, start: int, end: int) -> list[dict]:
    """SYN-scan a port range; return only open ports."""
    open_ports: list[dict] = []
    for port in range(start, end + 1):
        try:
            state = syn_scan(host, port)
        except Exception:
            state = "filtered"
        if state == "open":
            open_ports.append({"port": port, "state": "open", "banner": ""})
    return open_ports
