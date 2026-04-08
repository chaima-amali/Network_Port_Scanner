"""CLI entry point for the network port scanner."""

from __future__ import annotations

import argparse
import ipaddress
import json
from typing import Any

from scanner.risk import assess_risk
from scanner.syn_scanner import syn_scan, syn_scan_range
from scanner.tcp_scanner import scan_port, scan_range
from scanner.udp_scanner import udp_scan_range


def parse_port_range(port_range: str) -> tuple[int, int]:
    """Parse a start-end port range string into integer bounds."""

    try:
        start_text, end_text = port_range.split("-", 1)
        start = int(start_text)
        end = int(end_text)
    except ValueError as exc:
        raise ValueError("Ports must use the format start-end") from exc

    if start < 1 or end < 1 or start > end:
        raise ValueError("Ports must be positive and start must not exceed end")

    return start, end


def expand_target(target: str) -> list[str]:
    """Expand an IP address or CIDR target into a list of hosts."""

    network = ipaddress.ip_network(target, strict=False)
    return [str(host) for host in network.hosts()]


def build_argument_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser for the scanner."""

    parser = argparse.ArgumentParser(description="Network port scanner and insecure protocol detector")
    parser.add_argument("-t", "--target", required=True, help="Target IP or CIDR range")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range in start-end format")
    parser.add_argument("--syn", action="store_true", help="Use SYN scan")
    parser.add_argument("--udp", action="store_true", help="Enable UDP scan")
    parser.add_argument("--timeout", type=float, default=1.0, help="TCP connect timeout")
    parser.add_argument("--threads", type=int, default=100, help="Number of TCP scan threads")
    parser.add_argument("-o", "--output", help="Save results as JSON file")
    parser.add_argument("--html", help="Generate HTML report at the given path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show closed ports too")
    return parser


def _escape_html(value: Any) -> str:
    """Escape a value for inclusion in a simple HTML document."""

    text = str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def generate_json(output_path: str, payload: dict[str, Any]) -> None:
    """Write a JSON report to disk."""

    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def generate_html(output_path: str, payload: dict[str, Any]) -> None:
    """Write a simple HTML report to disk."""

    summary = payload.get("summary", {})
    hosts = payload.get("hosts", [])

    html_parts = [
        "<!doctype html>",
        "<html lang=\"en\">",
        "<head>",
        "<meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
        "<title>Network Port Scan Report</title>",
        "<style>body{font-family:Arial,sans-serif;margin:24px;}table{border-collapse:collapse;width:100%;margin:16px 0;}th,td{border:1px solid #ccc;padding:8px;text-align:left;}th{background:#f5f5f5;}code{white-space:pre-wrap;}</style>",
        "</head>",
        "<body>",
        "<h1>Network Port Scan Report</h1>",
        f"<p>Total open ports: {_escape_html(summary.get('total_open_ports', 0))}</p>",
        f"<p>Insecure count: {_escape_html(summary.get('insecure_count', 0))}</p>",
        f"<p>Highest severity found: {_escape_html(summary.get('highest_severity', 0))}</p>",
    ]

    for host_report in hosts:
        html_parts.append(f"<h2>{_escape_html(host_report.get('host', 'unknown host'))}</h2>")
        html_parts.append("<h3>TCP Results</h3>")
        html_parts.append("<table><tr><th>Port</th><th>State</th><th>Banner</th></tr>")
        for item in host_report.get("tcp_results", []):
            html_parts.append(
                f"<tr><td>{_escape_html(item.get('port', ''))}</td><td>{_escape_html(item.get('state', ''))}</td><td><code>{_escape_html(item.get('banner', ''))}</code></td></tr>"
            )
        html_parts.append("</table>")

        if host_report.get("udp_results"):
            html_parts.append("<h3>UDP Results</h3>")
            html_parts.append("<table><tr><th>Port</th><th>State</th></tr>")
            for item in host_report.get("udp_results", []):
                html_parts.append(
                    f"<tr><td>{_escape_html(item.get('port', ''))}</td><td>{_escape_html(item.get('state', ''))}</td></tr>"
                )
            html_parts.append("</table>")

        if host_report.get("risk_results"):
            html_parts.append("<h3>Risk Results</h3>")
            html_parts.append("<table><tr><th>Port</th><th>Name</th><th>Risk</th><th>Reason</th><th>Replace</th></tr>")
            for item in host_report.get("risk_results", []):
                html_parts.append(
                    f"<tr><td>{_escape_html(item.get('port', ''))}</td><td>{_escape_html(item.get('name', ''))}</td><td>{_escape_html(item.get('risk', ''))}</td><td>{_escape_html(item.get('reason', ''))}</td><td>{_escape_html(item.get('replace', ''))}</td></tr>"
                )
            html_parts.append("</table>")

    html_parts.extend(["</body>", "</html>"])

    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(html_parts))


def _scan_tcp_results(host: str, start: int, end: int, timeout: float, threads: int, use_syn: bool, verbose: bool) -> list[dict[str, int | str]]:
    """Collect TCP scan results using the requested scan mode."""

    if use_syn and verbose:
        results: list[dict[str, int | str]] = []
        for port in range(start, end + 1):
            try:
                state = syn_scan(host, port)
            except Exception:
                state = "filtered"
            results.append({"port": port, "state": state, "banner": ""})
        results.sort(key=lambda item: int(item["port"]))
        return results

    if use_syn:
        return syn_scan_range(host, start, end)

    if verbose:
        results: list[dict[str, int | str]] = []
        for port in range(start, end + 1):
            try:
                results.append(scan_port(host, port, timeout))
            except Exception:
                results.append({"port": port, "state": "closed", "banner": ""})
        results.sort(key=lambda item: int(item["port"]))
        return results

    return scan_range(host, start, end, timeout, threads)


def _print_summary(summary: dict[str, int]) -> None:
    """Print the scan summary to standard output."""

    print(f"Total open ports: {summary['total_open_ports']}")
    print(f"Insecure count: {summary['insecure_count']}")
    print(f"Highest severity found: {summary['highest_severity']}")


def main() -> None:
    """Run the command-line interface for the scanner."""

    parser = build_argument_parser()
    args = parser.parse_args()

    try:
        hosts = expand_target(args.target)
        start, end = parse_port_range(args.ports)
        udp_ports = list(range(start, end + 1))

        reports: list[dict[str, Any]] = []
        total_open_ports = 0
        insecure_count = 0
        highest_severity = 0

        for host in hosts:
            try:
                tcp_results = _scan_tcp_results(
                    host=host,
                    start=start,
                    end=end,
                    timeout=args.timeout,
                    threads=args.threads,
                    use_syn=args.syn,
                    verbose=args.verbose,
                )
                udp_results = udp_scan_range(host, udp_ports) if args.udp else []
                open_ports = [entry for entry in tcp_results if entry.get("state") == "open"]
                risk_results = assess_risk([{**entry, "host": host} for entry in open_ports])

                total_open_ports += len(open_ports)
                insecure_count += len(risk_results)
                if risk_results:
                    highest_severity = max(highest_severity, max(int(item["risk"]) for item in risk_results))

                reports.append(
                    {
                        "host": host,
                        "tcp_results": tcp_results,
                        "udp_results": udp_results,
                        "risk_results": risk_results,
                    }
                )
            except Exception as exc:
                print(f"Error scanning {host}: {exc}")

        summary = {
            "total_open_ports": total_open_ports,
            "insecure_count": insecure_count,
            "highest_severity": highest_severity,
        }

        _print_summary(summary)

        payload = {"summary": summary, "hosts": reports}
        if args.output:
            generate_json(args.output, payload)
        if args.html:
            generate_html(args.html, payload)
    except KeyboardInterrupt:
        print("Scan interrupted by user.")
    except ValueError as exc:
        print(f"Input error: {exc}")


if __name__ == "__main__":
    main()