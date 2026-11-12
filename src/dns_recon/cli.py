from __future__ import annotations
import argparse
import sys
from pathlib import Path

from rich.console import Console

from dns_recon import __version__
from dns_recon.dns_client import DNSClient, DNSLookupError
from dns_recon.formatters import format_console, format_json, format_markdown
from dns_recon.scoring import run_full_assessment


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dns-recon",
        description="DNS Health, Security Hygiene & Email Spoofing Reconnaissance Scanner",
    )
    parser.add_argument(
        "domain",
        help="Target domain to scan (e.g. example.com)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON to stdout",
    )
    parser.add_argument(
        "-o",
        "--report",
        metavar="PATH",
        help="Export detailed Markdown report to specified file path",
    )
    parser.add_argument(
        "-n",
        "--nameserver",
        action="append",
        metavar="IP",
        help="Custom nameserver(s) to query (e.g. 8.8.8.8). Can be specified multiple times.",
    )
    parser.add_argument(
        "-s",
        "--selectors",
        metavar="LIST",
        help="Comma-separated list of DKIM selectors to test (e.g. k1,mail,s1)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=3.0,
        help="DNS query timeout in seconds (default: 3.0)",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"dns-recon {__version__}",
    )
    return parser


def main(args: list[str] | None = None) -> int:
    parser = build_parser()
    parsed = parser.parse_args(args)

    selectors = None
    if parsed.selectors:
        selectors = [s.strip() for s in parsed.selectors.split(",") if s.strip()]

    client = DNSClient(nameservers=parsed.nameserver, timeout=parsed.timeout)
    console = Console()
    err_console = Console(stderr=True)

    try:
        report = run_full_assessment(
            domain=parsed.domain,
            client=client,
            selectors=selectors,
        )
    except DNSLookupError as e:
        if parsed.json:
            import json
            print(json.dumps({"error": str(e), "domain": parsed.domain}))
        else:
            err_console.print(f"[bold red]DNS Lookup Error:[/bold red] {e}")
        return 1
    except Exception as e:
        if parsed.json:
            import json
            print(json.dumps({"error": f"Unexpected error: {e}", "domain": parsed.domain}))
        else:
            err_console.print(f"[bold red]Scan Failed:[/bold red] {e}")
        return 1

    if parsed.json:
        print(format_json(report))
    else:
        format_console(report, console=console)

    if parsed.report:
        try:
            report_path = Path(parsed.report)
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(format_markdown(report), encoding="utf-8")
            if not parsed.json:
                console.print(f"\n[bold green]Report saved to:[/bold green] {report_path.resolve()}")
        except Exception as e:
            err_console.print(f"[bold red]Failed to write report file:[/bold red] {e}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
