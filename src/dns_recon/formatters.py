from __future__ import annotations
import json
from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from dns_recon.models import AssessmentReport, InfoGatherResult, Severity

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

    bimi_status = "✅ Published" if report.bimi.is_valid else ("⚠️ Incomplete" if report.bimi.record else "ℹ️ None")
    bimi_summary = report.bimi.location if report.bimi.location else "No BIMI logo published"
    lines.append(f"| **BIMI** | {bimi_status} | {bimi_summary} |")

    mta_status = "✅ Enforced" if report.mta_sts.has_mta_sts else "⚠️ Missing"
    mta_summary = f"MTA-STS: {'Yes' if report.mta_sts.has_mta_sts else 'No'}, TLS-RPT: {'Yes' if report.mta_sts.has_tls_rpt else 'No'}"
    lines.append(f"| **MTA-STS & TLS-RPT** | {mta_status} | {mta_summary} |")

    takeover_vuln = report.takeover.dangling_count > 0
    takeover_status = "🚨 VULNERABLE" if takeover_vuln else "✅ Secure"
    takeover_summary = f"{report.takeover.dangling_count} dangling CNAME(s) found" if takeover_vuln else f"{len(report.takeover.cname_checks)} CNAME(s) verified active"
    lines.append(f"| **Subdomain Takeover** | {takeover_status} | {takeover_summary} |")

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
        lines.append(f"SPF:     {report.spf.record}")
    if report.dmarc.record:
        lines.append(f"DMARC:   {report.dmarc.record}")
    if report.bimi.record:
        lines.append(f"BIMI:    {report.bimi.record}")
    if report.mta_sts.mta_sts_record:
        lines.append(f"MTA-STS: {report.mta_sts.mta_sts_record}")
    if report.mta_sts.tls_rpt_record:
        lines.append(f"TLS-RPT: {report.mta_sts.tls_rpt_record}")
    for s in report.dkim.found_selectors:
        lines.append(f"DKIM ({s.selector}): {s.record}")
    for mx in report.mx.records:
        lines.append(f"MX:      pref={mx.preference} host={mx.exchange}")
    for ns in report.nameservers.nameservers:
        lines.append(f"NS:      {ns}")
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

    # BIMI Row
    if report.bimi.is_valid:
        bimi_status = Text("PUBLISHED", style="bold green")
    elif report.bimi.record:
        bimi_status = Text("WARN", style="yellow")
    else:
        bimi_status = Text("NONE", style="dim")
    overview_table.add_row(
        "BIMI (Brand Indicators)",
        bimi_status,
        report.bimi.location or "No BIMI record published",
    )

    # MTA-STS & TLS-RPT Row
    if report.mta_sts.has_mta_sts and report.mta_sts.has_tls_rpt:
        mta_status = Text("ENFORCED", style="bold green")
    elif report.mta_sts.has_mta_sts or report.mta_sts.has_tls_rpt:
        mta_status = Text("PARTIAL", style="yellow")
    else:
        mta_status = Text("MISSING", style="dim")
    overview_table.add_row(
        "MTA-STS & TLS-RPT",
        mta_status,
        f"MTA-STS: {'Yes' if report.mta_sts.has_mta_sts else 'No'} • TLS-RPT: {'Yes' if report.mta_sts.has_tls_rpt else 'No'}",
    )

    # Subdomain Takeover Row
    if report.takeover.dangling_count > 0:
        takeover_status = Text(f"{report.takeover.dangling_count} DANGLING", style="bold red blink")
    else:
        takeover_status = Text("SECURE", style="bold green")
    overview_table.add_row(
        "Subdomain Takeover",
        takeover_status,
        f"{report.takeover.dangling_count} dangling CNAMEs" if report.takeover.dangling_count > 0 else f"{len(report.takeover.cname_checks)} CNAME targets checked",
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


def format_osint_json(result: InfoGatherResult) -> str:
    """Format OSINT result as pretty-printed JSON."""
    return json.dumps(result.to_dict(), indent=2)


def format_osint_markdown(result: InfoGatherResult) -> str:
    """Format OSINT information gathering result as Markdown."""
    lines = [
        f"# Information Gathering & OSINT Report: {result.domain}",
        f"**Generated:** {result.timestamp} (UTC)  ",
        f"**Detected Cloud/Host:** {result.detected_host or 'Undetermined'}  ",
        "",
        "## Resolved IP Addresses",
        "| IP Address | Version | Reverse PTR | Cloud / Provider |",
        "| :--- | :--- | :--- | :--- |",
    ]
    for ip in result.ips:
        lines.append(f"| `{ip.ip}` | {ip.version} | {ip.ptr or '-'} | {ip.provider or '-'} |")

    lines.append("")
    lines.append("## Discovered Subdomains & Infrastructure")
    lines.append(f"Total Discovered: {len(result.subdomains)}")
    lines.append("")
    lines.append("| Subdomain | Record Type | Target / Resolved IP | Live Status | Source |")
    lines.append("| :--- | :--- | :--- | :--- | :--- |")
    for s in result.subdomains:
        status_icon = "🟢 Live" if s.is_live else "⚪ Inactive"
        lines.append(f"| `{s.subdomain}` | {s.record_type} | `{s.target}` | {status_icon} | {s.source} |")

    return "\n".join(lines)


def format_osint_console(result: InfoGatherResult, console: Console | None = None) -> None:
    """Render OSINT information gathering report in terminal using Rich."""
    if console is None:
        console = Console()

    header_text = Text()
    header_text.append("RECONNAISSANCE & INFORMATION GATHERING\n", style="bold magenta")
    header_text.append(f"Domain: {result.domain}  •  Host: ", style="dim")
    header_text.append(f"{result.detected_host or 'Undetermined'}", style="bold yellow")
    header_text.append(f"  •  Time: {result.timestamp[:19]} UTC", style="dim")

    console.print(Panel(header_text, border_style="magenta", expand=False))

    # IP Table
    if result.ips:
        ip_table = Table(title="Target IP Addresses & Reverse DNS (PTR)", border_style="dim")
        ip_table.add_column("IP Address", style="bold cyan")
        ip_table.add_column("Type", justify="center")
        ip_table.add_column("Reverse PTR")
        ip_table.add_column("Provider / Cloud")
        for ip in result.ips:
            ip_table.add_row(ip.ip, ip.version, ip.ptr or "-", ip.provider or "-")
        console.print(ip_table)

    # Subdomain Table
    sub_table = Table(title=f"Discovered Subdomains ({len(result.subdomains)} found)", border_style="dim")
    sub_table.add_column("Subdomain", style="bold white")
    sub_table.add_column("Type", justify="center")
    sub_table.add_column("Resolved Target", style="cyan")
    sub_table.add_column("Status", justify="center")
    sub_table.add_column("Source", style="dim")

    for s in result.subdomains:
        status_text = Text("LIVE", style="bold green") if s.is_live else Text("INACTIVE", style="dim")
        sub_table.add_row(s.subdomain, s.record_type, s.target, status_text, s.source)

    console.print(sub_table)

