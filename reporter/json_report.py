"""JSON report generator — Person B's module.

Serialises all scan findings to a machine-readable JSON file.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any


def generate_json(
    findings_by_host: list[dict[str, Any]],
    output_path: str | Path,
    *,
    summary: dict[str, Any] | None = None,
) -> None:
    """Write a structured JSON report to *output_path*.

    Args:
        findings_by_host: List of per-host dicts, each containing:
                          host, tcp_results, udp_results, risk_results.
        output_path:      Destination file path (created/overwritten).
        summary:          Optional aggregate statistics dict.
    """
    payload: dict[str, Any] = {
        "meta": {
            "tool":       "Network Port Scanner + Insecure Protocol Detector",
            "generated":  datetime.datetime.now().isoformat(timespec="seconds"),
            "version":    "1.0",
        },
        "summary": summary or {},
        "hosts":   findings_by_host,
    }

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, default=str)

    print(f"[+] JSON report saved → {path.resolve()}")
