from __future__ import annotations
import json
from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from dns_recon.models import AssessmentReport, Severity

if TYPE_CHECKING:
    pass


SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "green",
}


def format_json(report: AssessmentReport) -> str:
    """Format assessment report as pretty-printed JSON."""
    return json.dumps(report.to_dict(), indent=2)


def format_markdown(report: AssessmentReport) -> str:
    """Format assessment report as detailed Markdown document."""
    lines = [
        f"# DNS Health & Email Spoofing Assessment: {report.domain}",
        f"**Generated:** {report.timestamp} (UTC)  ",
        f"**Security Score:** **{report.score} / 100**  ",
        f"**Security Grade:** **{report.grade}**  ",
        "",
        "## Executive Summary",
        "| Protocol / Area | Status | Key Highlights |",
        "| :--- | :--- | :--- |",
    ]

    # Protocol status rows
    spf_status = "✅ Valid" if report.spf.is_valid else "❌ Broken/Missing"
    spf_summary = (
        f"`{report.spf.all_mechanism}` ({report.spf.lookup_count} DNS lookups)"
        if report.spf.record
        else "No SPF record published"
    )
    lines.append(f"| **SPF** | {spf_status} | {spf_summary} |")

    dmarc_status = "✅ Enforcing" if report.dmarc.policy in ("reject", "quarantine") else "⚠️ Vulnerable"
    dmarc_summary = (
        f"Policy: `p={report.dmarc.policy}` (pct={report.dmarc.pct}%)"
        if report.dmarc.record
        else "No DMARC record"
    )
    lines.append(f"| **DMARC** | {dmarc_status} | {dmarc_summary} |")

    dkim_count = len(report.dkim.found_selectors)
    dkim_status = "✅ Discovered" if dkim_count > 0 else "ℹ️ Unverified"
    dkim_summary = f"{dkim_count} selector(s) found" if dkim_count > 0 else "No default selectors found"
    lines.append(f"| **DKIM** | {dkim_status} | {dkim_summary} |")

    dnssec_status = "✅ Enabled" if report.dnssec.is_enabled else "⚠️ Disabled"
    dnssec_summary = (
        f"DNSKEY: {report.dnssec.dnskey_count}, DS: {report.dnssec.ds_count}"
        if report.dnssec.is_enabled
        else "Zone is not cryptographically signed"
    )
    lines.append(f"| **DNSSEC** | {dnssec_status} | {dnssec_summary} |")

    axfr_vuln = any(c.vulnerable for c in report.nameservers.axfr_checks)
    ns_status = "🚨 AXFR OPEN" if axfr_vuln else ("✅ Secure" if len(report.nameservers.nameservers) >= 2 else "⚠️ Low Redundancy")
    ns_summary = f"{len(report.nameservers.nameservers)} nameserver(s); AXFR: {'VULNERABLE' if axfr_vuln else 'Denied'}"
    lines.append(f"| **Nameservers & AXFR** | {ns_status} | {ns_summary} |")

    mx_count = len(report.mx.records)
    mx_status = "✅ Active" if mx_count > 0 else "ℹ️ None"
    mx_summary = f"{mx_count} MX server(s) configured"
    lines.append(f"| **MX Records** | {mx_status} | {mx_summary} |")

    lines.append("")
    lines.append("## Findings & Remediation Guidance")
    if not report.all_findings:
        lines.append("No security vulnerabilities or hygiene warnings identified.")
    else:
        lines.append("| Severity | Finding | Details & Impact | Recommended Remediation |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for f in report.all_findings:
            lines.append(f"| **{f.severity.value}** | {f.title} | {f.description} | {f.remediation} |")

    lines.append("")
    lines.append("## Published Records")
    lines.append("```text")
    if report.spf.record:
        lines.append(f"SPF:   {report.spf.record}")
    if report.dmarc.record:
        lines.append(f"DMARC: {report.dmarc.record}")
    for s in report.dkim.found_selectors:
        lines.append(f"DKIM ({s.selector}): {s.record}")
    for mx in report.mx.records:
        lines.append(f"MX:    pref={mx.preference} host={mx.exchange}")
    for ns in report.nameservers.nameservers:
        lines.append(f"NS:    {ns}")
    lines.append("```")

    return "\n".join(lines)


def format_console(report: AssessmentReport, console: Console | None = None) -> None:
    """Render beautiful terminal report using Rich tables and panels."""
    if console is None:
        console = Console()

    # Determine score badge style
    if report.score >= 85:
        score_color = "bold green"
    elif report.score >= 60:
        score_color = "bold yellow"
    else:
        score_color = "bold red"

    # Header Panel
    header_text = Text()
    header_text.append("DNS HEALTH & EMAIL SPOOFING RECONNAISSANCE\n", style="bold cyan")
    header_text.append(f"Target: {report.domain}  •  Score: ", style="dim")
    header_text.append(f"{report.score}/100", style=score_color)
    header_text.append(f" (Grade {report.grade})", style=score_color)
    header_text.append(f"  •  Time: {report.timestamp[:19]} UTC", style="dim")

    console.print(Panel(header_text, border_style="cyan", expand=False))

    # Overview Table
    overview_table = Table(title="Email Authentication & DNS Security Posture", border_style="dim")
    overview_table.add_column("Security Area", style="bold white")
    overview_table.add_column("Status", justify="center")
    overview_table.add_column("Details")

    # SPF Row
    if report.spf.is_valid:
        spf_status = Text("PASS", style="bold green") if report.spf.all_mechanism == "-all" else Text("WARN", style="yellow")
    else:
        spf_status = Text("FAIL", style="bold red")
    overview_table.add_row(
        "SPF (Sender Policy Framework)",
        spf_status,
        f"{report.spf.all_mechanism or 'No qualifier'} ({report.spf.lookup_count} lookups)" if report.spf.record else "No SPF record published",
    )

    # DMARC Row
    if report.dmarc.policy in ("reject", "quarantine"):
        dmarc_status = Text("ENFORCING", style="bold green")
    elif report.dmarc.policy == "none":
        dmarc_status = Text("MONITORING", style="bold yellow")
    else:
        dmarc_status = Text("MISSING", style="bold red")
    overview_table.add_row(
        "DMARC (Anti-Spoofing Policy)",
        dmarc_status,
        f"p={report.dmarc.policy} (pct={report.dmarc.pct}%)" if report.dmarc.record else "No DMARC record",
    )

    # DKIM Row
    dkim_count = len(report.dkim.found_selectors)
    dkim_status = Text(f"{dkim_count} FOUND", style="bold green" if dkim_count > 0 else "dim")
    overview_table.add_row(
        "DKIM Selectors",
        dkim_status,
        f"Found: {', '.join([s.selector for s in report.dkim.found_selectors])}" if dkim_count > 0 else "None discovered among common selectors",
    )

    # DNSSEC Row
    dnssec_status = Text("ENABLED", style="bold green") if report.dnssec.is_enabled else Text("DISABLED", style="yellow")
    overview_table.add_row(
        "DNSSEC Validation",
        dnssec_status,
        f"DNSKEY={report.dnssec.dnskey_count}, DS={report.dnssec.ds_count}" if report.dnssec.is_enabled else "Zone is unsigned",
    )

    # Nameservers & AXFR
    axfr_vuln = any(c.vulnerable for c in report.nameservers.axfr_checks)
    if axfr_vuln:
        axfr_status = Text("AXFR LEAK", style="bold red blink")
    else:
        axfr_status = Text("SECURE", style="bold green") if len(report.nameservers.nameservers) >= 2 else Text("LOW REDUNDANCY", style="yellow")
    overview_table.add_row(
        "Nameservers & Zone Transfer",
        axfr_status,
        f"{len(report.nameservers.nameservers)} NS; AXFR {'VULNERABLE' if axfr_vuln else 'Denied'}",
    )

    # MX Row
    mx_status = Text(f"{len(report.mx.records)} ACTIVE", style="bold green" if report.mx.records else "dim")
    overview_table.add_row(
        "MX Records",
        mx_status,
        f"{', '.join([r.exchange for r in report.mx.records])}" if report.mx.records else "No MX records",
    )

    console.print(overview_table)

    # Findings Table
    if report.all_findings:
        findings_table = Table(title="Security Findings & Remediation", border_style="dim")
        findings_table.add_column("Severity", justify="center")
        findings_table.add_column("Finding", style="bold white")
        findings_table.add_column("Remediation", style="green")

        for f in report.all_findings:
            sev_style = SEVERITY_STYLES.get(f.severity, "white")
            findings_table.add_row(
                Text(f.severity.value, style=sev_style),
                f.title,
                f.remediation,
            )

        console.print(findings_table)
    else:
        console.print("[green]✔ No security warnings or misconfigurations identified.[/green]")

