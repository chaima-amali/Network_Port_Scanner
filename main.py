"""CLI entry point for the Network Port Scanner + Insecure Protocol Detector.

Person A owns this file.  It wires together:
  - scanner/tcp_scanner.py   (Person A)
  - scanner/syn_scanner.py   (Person A)
  - scanner/udp_scanner.py   (Person A)
  - scanner/banner.py        (Person B) — banner enrichment
  - scanner/risk.py          (Person B) — risk scoring
  - reporter/terminal.py     (Person B) — Rich terminal output
  - reporter/json_report.py  (Person B) — JSON export
  - reporter/html_report.py  (Person B) — HTML report
"""

from __future__ import annotations

import argparse
import ipaddress
from typing import Any

from scanner.banner import enrich_with_banners
from scanner.risk import assess_risk, summarise
from scanner.syn_scanner import syn_scan, syn_scan_range
from scanner.tcp_scanner import scan_port, scan_range
from scanner.udp_scanner import udp_scan_range

from reporter.terminal import console, print_open_ports, print_findings, print_summary
from reporter.json_report import generate_json
from reporter.html_report import generate_html


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Network Port Scanner + Insecure Protocol Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-t", "--target",  required=True, help="Target IP or CIDR range")
    parser.add_argument("-p", "--ports",   default="1-1024", help="Port range e.g. 1-65535")
    parser.add_argument("--syn",           action="store_true", help="SYN scan (requires root)")
    parser.add_argument("--udp",           action="store_true", help="Enable UDP scanning")
    parser.add_argument("--timeout",       type=float, default=1.0)
    parser.add_argument("--threads",       type=int,   default=100)
    parser.add_argument("-o", "--output",  help="Save results to JSON file")
    parser.add_argument("--html",          help="Generate HTML report at given path")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def parse_port_range(port_range: str) -> tuple[int, int]:
    try:
        start_s, end_s = port_range.split("-", 1)
        start, end = int(start_s), int(end_s)
    except ValueError as exc:
        raise ValueError("Ports must use the format start-end") from exc
    if start < 1 or end < 1 or start > end:
        raise ValueError("Ports must be positive and start must not exceed end")
    return start, end


def expand_target(target: str) -> list[str]:
    network = ipaddress.ip_network(target, strict=False)
    return [str(host) for host in network.hosts()]


def _scan_tcp(host, start, end, timeout, threads, use_syn, verbose):
    if use_syn:
        if verbose:
            results = []
            for port in range(start, end + 1):
                try:
                    state = syn_scan(host, port)
                except Exception:
                    state = "filtered"
                results.append({"port": port, "state": state, "banner": ""})
            return sorted(results, key=lambda x: x["port"])
        return syn_scan_range(host, start, end)
    if verbose:
        results = []
        for port in range(start, end + 1):
            try:
                results.append(scan_port(host, port, timeout))
            except Exception:
                results.append({"port": port, "state": "closed", "banner": ""})
        return sorted(results, key=lambda x: x["port"])
    return scan_range(host, start, end, timeout, threads)


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()

    try:
        hosts = expand_target(args.target)
        start, end = parse_port_range(args.ports)

        all_host_reports: list[dict[str, Any]] = []
        all_findings: list[dict] = []

        console.rule("[bold cyan]Network Port Scanner[/bold cyan]")

        for host in hosts:
            try:
                console.print(f"[bold]Scanning {host} …[/bold]")

                tcp_results = _scan_tcp(host, start, end, args.timeout, args.threads, args.syn, args.verbose)

                open_ports = [e for e in tcp_results if e.get("state") == "open"]
                open_ports = enrich_with_banners(open_ports, host)

                enriched_map = {e["port"]: e for e in open_ports}
                tcp_results = [enriched_map.get(e["port"], e) for e in tcp_results]

                udp_results = udp_scan_range(host, list(range(start, end + 1))) if args.udp else []

                risk_results = assess_risk([{**e, "host": host} for e in open_ports])
                all_findings.extend(risk_results)

                display_ports = open_ports if not args.verbose else tcp_results
                print_open_ports(host, display_ports)
                print_findings(host, risk_results)

                all_host_reports.append({
                    "host":         host,
                    "tcp_results":  tcp_results,
                    "udp_results":  udp_results,
                    "risk_results": risk_results,
                })

            except Exception as exc:
                console.print(f"[red]Error scanning {host}:[/red] {exc}")

        stats = summarise(all_findings)
        print_summary(stats)

        if args.output:
            generate_json(all_host_reports, args.output, summary=stats)

        if args.html:
            generate_html(all_host_reports, args.html, host=args.target, summary=stats)

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
    except ValueError as exc:
        console.print(f"[red]Input error:[/red] {exc}")


if __name__ == "__main__":
    main()
