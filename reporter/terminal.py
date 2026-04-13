"""Terminal reporter — Person B's module.

Produces colored, human-readable output in the terminal using the
Rich library.  Two tables are printed for each host:
  1. All open ports (with banner)
  2. Insecure protocol findings with severity badges
"""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Shared console instance — import this if you need to print elsewhere
console = Console()

# Severity → Rich colour mapping
_SEVERITY_COLOURS: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange1",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold green",
    "INFO":     "dim",
}


def _severity_badge(severity: str) -> Text:
    """Return a coloured Rich Text badge for the given severity label."""
    colour = _SEVERITY_COLOURS.get(severity, "white")
    return Text(f" {severity} ", style=f"{colour} on grey15")


# ── Open-ports table ─────────────────────────────────────────────────────────

def print_open_ports(host: str, open_ports: list[dict]) -> None:
    """Print a table of all open TCP ports for *host*.

    Args:
        host:       Target IP address.
        open_ports: List of dicts with keys: port, state, banner.
    """
    table = Table(
        title=f"Open Ports — {host}",
        box=box.ROUNDED,
        show_lines=True,
        highlight=True,
    )
    table.add_column("Port",   style="cyan bold",  no_wrap=True, width=8)
    table.add_column("State",  style="green",       width=10)
    table.add_column("Banner", style="white dim",   overflow="fold")

    if not open_ports:
        table.add_row("-", "No open ports found", "")
    else:
        for entry in sorted(open_ports, key=lambda e: int(e["port"])):
            table.add_row(
                str(entry["port"]),
                entry.get("state", "open"),
                entry.get("banner", "") or "[dim]–[/dim]",
            )

    console.print(table)


# ── Risk findings table ───────────────────────────────────────────────────────

def print_findings(host: str, findings: list[dict]) -> None:
    """Print a colour-coded table of insecure protocol findings for *host*.

    Args:
        host:     Target IP address.
        findings: Output of scanner.risk.assess_risk().
    """
    if not findings:
        console.print(
            Panel(
                "[bold green]✔ No insecure protocols detected[/bold green]",
                title=f"Risk Analysis — {host}",
                border_style="green",
            )
        )
        return

    table = Table(
        title=f"⚠  Insecure Protocol Findings — {host}",
        box=box.ROUNDED,
        show_lines=True,
        highlight=True,
    )
    table.add_column("Port",       style="cyan bold",   no_wrap=True, width=7)
    table.add_column("Protocol",   style="bold white",  width=14)
    table.add_column("Severity",   width=12)
    table.add_column("Score",      style="bold",        width=7)
    table.add_column("Risk Reason",                     overflow="fold")
    table.add_column("Recommendation",                  overflow="fold")
    table.add_column("Banner",     style="dim",         overflow="fold")

    for f in findings:
        severity = f.get("severity", "INFO")
        score_colour = _SEVERITY_COLOURS.get(severity, "white")
        table.add_row(
            str(f["port"]),
            str(f["name"]),
            _severity_badge(severity),
            Text(f"{f['risk']}/10", style=score_colour),
            str(f["reason"]),
            str(f["replace"]),
            f.get("banner", "") or "–",
        )

    console.print(table)


# ── Summary panel ─────────────────────────────────────────────────────────────

def print_summary(summary: dict) -> None:
    """Print an overall scan summary panel.

    Args:
        summary: Dict from scanner.risk.summarise() containing keys:
                 total, critical, high, medium, low, max_score.
    """
    lines = [
        f"[bold]Total insecure findings:[/bold] {summary.get('total', 0)}",
        f"  [bold red]CRITICAL:[/bold red] {summary.get('critical', 0)}",
        f"  [bold orange1]HIGH:[/bold orange1]     {summary.get('high', 0)}",
        f"  [bold yellow]MEDIUM:[/bold yellow]   {summary.get('medium', 0)}",
        f"  [bold green]LOW:[/bold green]      {summary.get('low', 0)}",
        f"[bold]Highest score:[/bold] {summary.get('max_score', 0)}/10",
    ]
    border = "red" if summary.get("critical", 0) > 0 else "yellow"
    console.print(
        Panel("\n".join(lines), title="Scan Summary", border_style=border)
    )
