"""Risk assessment helpers for detected open ports."""

from __future__ import annotations

from scanner.protocols import INSECURE_PROTOCOLS


def assess_risk(open_ports: list[dict[str, int | str]]) -> list[dict[str, int | str]]:
    """Map open ports to known insecure services and their mitigation guidance."""

    findings: list[dict[str, int | str]] = []

    for port_info in open_ports:
        port = int(port_info.get("port", -1))
        protocol = INSECURE_PROTOCOLS.get(port)
        if protocol is None:
            continue

        finding = {
            "port": port,
            "name": protocol["name"],
            "risk": protocol["risk"],
            "reason": protocol["reason"],
            "replace": protocol["replace"],
        }
        if "host" in port_info:
            finding["host"] = port_info["host"]
        findings.append(finding)

    findings.sort(key=lambda item: (-int(item["risk"]), int(item["port"])))
    return findings