"""HTML report generator — Person B's module.

Renders a styled, professional HTML security audit report using the
Jinja2 template in reporter/templates/report.html.
"""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import Any

try:
    from jinja2 import Environment, FileSystemLoader  # type: ignore
    _JINJA2_AVAILABLE = True
except ImportError:
    _JINJA2_AVAILABLE = False


def generate_html(
    findings_by_host: list[dict[str, Any]],
    output_path: str | Path,
    *,
    host: str = "Multiple Hosts",
    summary: dict[str, Any] | None = None,
    template_dir: str | Path | None = None,
) -> None:
    """Render an HTML report from scan findings and write it to *output_path*.

    Args:
        findings_by_host: List of per-host result dicts.
        output_path:      Destination .html file path.
        host:             Display label for the report header.
        summary:          Aggregate stats dict (from scanner.risk.summarise).
        template_dir:     Override the directory containing report.html.
                          Defaults to reporter/templates/ relative to this file.

    Raises:
        ImportError: If Jinja2 is not installed.
    """
    if not _JINJA2_AVAILABLE:
        raise ImportError(
            "Jinja2 is required for HTML reports: pip install jinja2"
        )

    # Locate the templates directory
    if template_dir is None:
        template_dir = Path(__file__).parent / "templates"
    else:
        template_dir = Path(template_dir)

    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=True,          # XSS-safe by default
    )
    template = env.get_template("report.html")

    rendered = template.render(
        host=host,
        hosts=findings_by_host,
        summary=summary or {},
        scan_time=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    with out.open("w", encoding="utf-8") as fh:
        fh.write(rendered)

    print(f"[+] HTML report saved → {out.resolve()}")
