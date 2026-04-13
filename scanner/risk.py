"""Risk scoring engine — Person B's module.

Cross-references open ports against the insecure protocol database
(protocols.py) and produces structured findings with severity labels
and remediation recommendations.
"""

from __future__ import annotations

from scanner.protocols import INSECURE_PROTOCOLS

# ── Severity mapping ─────────────────────────────────────────────────────────

_SEVERITY_BANDS: list[tuple[range, str]] = [
    (range(9, 11), "CRITICAL"),
    (range(7, 9),  "HIGH"),
    (range(4, 7),  "MEDIUM"),
    (range(1, 4),  "LOW"),
]


def get_severity(score: int) -> str:
    """Map a numeric risk score (1–10) to a severity label.

    Args:
        score: Integer between 1 and 10 inclusive.

    Returns:
        One of: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', or 'INFO'.
    """
    for band, label in _SEVERITY_BANDS:
        if score in band:
            return label
    return "INFO"


# ── Risk assessment ──────────────────────────────────────────────────────────

def assess_risk(open_ports: list[dict]) -> list[dict]:
    """Cross-reference open ports against the insecure protocol database.

    Args:
        open_ports: List of dicts from the scanner, each containing at
                    minimum {"port": int, "state": str, "banner": str}.
                    An optional "host" key is preserved if present.

    Returns:
        List of finding dicts — one per flagged port — containing:
            port           : int  – the port number
            name           : str  – protocol name
            risk           : int  – risk score 1–10
            severity       : str  – CRITICAL / HIGH / MEDIUM / LOW
            reason         : str  – plain-English risk explanation
            replace        : str  – recommended secure alternative
            banner         : str  – raw service banner (may be empty)
            host           : str  – target host (if provided)
    """
    findings: list[dict] = []

    for entry in open_ports:
        port = int(entry.get("port", 0))

        if port not in INSECURE_PROTOCOLS:
            continue  # Safe or unknown port — skip

        proto = INSECURE_PROTOCOLS[port]
        risk_score = int(proto["risk"])

        finding = {
            "port":         port,
            "name":         proto["name"],
            "risk":         risk_score,
            "severity":     get_severity(risk_score),
            "reason":       proto["reason"],
            "replace":      proto["replace"],
            "banner":       entry.get("banner", ""),
        }

        # Preserve optional host key
        if "host" in entry:
            finding["host"] = entry["host"]

        findings.append(finding)

    # Sort by descending risk score so the worst offenders appear first
    findings.sort(key=lambda f: f["risk"], reverse=True)
    return findings


# ── Summary statistics ───────────────────────────────────────────────────────

def summarise(findings: list[dict]) -> dict:
    """Compute aggregate statistics across all findings.

    Args:
        findings: Output of assess_risk().

    Returns:
        Dict with keys: total, critical, high, medium, low, max_score.
    """
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    max_score = 0

    for f in findings:
        severity = f.get("severity", "INFO")
        if severity in counts:
            counts[severity] += 1
        score = int(f.get("risk", 0))
        if score > max_score:
            max_score = score

    return {
        "total":    len(findings),
        "critical": counts["CRITICAL"],
        "high":     counts["HIGH"],
        "medium":   counts["MEDIUM"],
        "low":      counts["LOW"],
        "max_score": max_score,
    }
