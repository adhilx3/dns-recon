from __future__ import annotations
import argparse
import sys
from pathlib import Path

from rich.console import Console

from dns_recon import __version__
from dns_recon.analyzers.osint import gather_information
from dns_recon.dns_client import DNSClient, DNSLookupError
from dns_recon.formatters import (
    format_console,
    format_json,
    format_markdown,
    format_osint_console,
    format_osint_json,
    format_osint_markdown,
)
from dns_recon.scoring import normalize_domain, run_full_assessment


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
        "--info",
        "--osint",
        dest="osint",
        action="store_true",
        help="Conduct reconnaissance & information gathering (IP, reverse PTR, subdomains)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run comprehensive scan: Security Audit + OSINT Information Gathering",
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

    clean_domain = normalize_domain(parsed.domain)

    # 1. OSINT Mode only
    if parsed.osint and not parsed.all:
        try:
            if not client.domain_exists(clean_domain):
                raise DNSLookupError(f"Target domain '{clean_domain}' does not exist (NXDOMAIN).")
            osint_result = gather_information(client, clean_domain)
        except DNSLookupError as e:
            if parsed.json:
                import json
                print(json.dumps({"error": str(e), "domain": clean_domain}))
            else:
                err_console.print(f"[bold red]DNS Lookup Error:[/bold red] {e}")
            return 1
        except Exception as e:
            if parsed.json:
                import json
                print(json.dumps({"error": f"Unexpected error: {e}", "domain": clean_domain}))
            else:
                err_console.print(f"[bold red]OSINT Failed:[/bold red] {e}")
            return 1

        if parsed.json:
            print(format_osint_json(osint_result))
        else:
            format_osint_console(osint_result, console=console)

        if parsed.report:
            try:
                report_path = Path(parsed.report)
                report_path.parent.mkdir(parents=True, exist_ok=True)
                report_path.write_text(format_osint_markdown(osint_result), encoding="utf-8")
                if not parsed.json:
                    console.print(f"\n[bold green]Report saved to:[/bold green] {report_path.resolve()}")
            except Exception as e:
                err_console.print(f"[bold red]Failed to write report file:[/bold red] {e}")

        return 0

    # 2. Security Audit Mode (or --all)
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

    osint_result = None
    if parsed.all:
        try:
            osint_result = gather_information(client, clean_domain)
        except Exception as e:
            err_console.print(f"[yellow]Warning: OSINT gathering encountered error:[/yellow] {e}")

    if parsed.json:
        out_dict = report.to_dict()
        if osint_result:
            out_dict["osint"] = osint_result.to_dict()
        import json
        print(json.dumps(out_dict, indent=2))
    else:
        format_console(report, console=console)
        if osint_result:
            console.print("\n")
            format_osint_console(osint_result, console=console)

    if parsed.report:
        try:
            report_path = Path(parsed.report)
            report_path.parent.mkdir(parents=True, exist_ok=True)
            md_text = format_markdown(report)
            if osint_result:
                md_text += "\n\n---\n\n" + format_osint_markdown(osint_result)
            report_path.write_text(md_text, encoding="utf-8")
            if not parsed.json:
                console.print(f"\n[bold green]Report saved to:[/bold green] {report_path.resolve()}")
        except Exception as e:
            err_console.print(f"[bold red]Failed to write report file:[/bold red] {e}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
