from __future__ import annotations
from datetime import datetime, timezone

from urllib.parse import urlparse

from dns_recon.dns_client import DNSClient, DNSLookupError
from dns_recon.models import AssessmentReport, Finding, Severity
from dns_recon.analyzers.spf import analyze_spf
from dns_recon.analyzers.dmarc import analyze_dmarc
from dns_recon.analyzers.dkim import analyze_dkim
from dns_recon.analyzers.dnssec import analyze_dnssec
from dns_recon.analyzers.nameserver import analyze_nameservers
from dns_recon.analyzers.mx import analyze_mx

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def normalize_domain(domain_or_url: str) -> str:
    """Extract clean domain/hostname from user input (stripping protocols, paths, ports, trailing dots)."""
    text = domain_or_url.strip()
    if "://" in text:
        parsed = urlparse(text)
        host = parsed.netloc or parsed.path
    else:
        # Strip leading slashes, path parts, query strings, fragments
        host = text.lstrip("/").split("/")[0].split("?")[0].split("#")[0]

    # Strip port if present (e.g. example.com:8080)
    if ":" in host:
        host = host.split(":")[0]

    return host.strip().lower().rstrip(".")


def calculate_score(findings: list[Finding]) -> int:
    """Calculate security score from 0 to 100 based on severity penalties."""
    score = 100
    for finding in findings:
        score -= finding.severity.penalty
    return max(0, min(100, score))


def determine_grade(score: int) -> str:
    """Determine letter grade based on security score."""
    if score >= 95:
        return "A+"
    elif score >= 85:
        return "A"
    elif score >= 75:
        return "B"
    elif score >= 60:
        return "C"
    elif score >= 45:
        return "D"
    else:
        return "F"


def run_full_assessment(
    domain: str,
    client: DNSClient | None = None,
    selectors: list[str] | None = None,
) -> AssessmentReport:
    """
    Run complete reconnaissance assessment against domain across:
    - SPF
    - DMARC
    - DKIM
    - DNSSEC
    - Nameservers / AXFR
    - MX
    """
    if client is None:
        client = DNSClient()

    # Clean and normalize domain input (handles URLs, paths, ports)
    domain = normalize_domain(domain)

    if not domain or not client.domain_exists(domain):
        raise DNSLookupError(f"Target domain '{domain}' does not exist (NXDOMAIN).")

    spf_res = analyze_spf(client, domain)
    dmarc_res = analyze_dmarc(client, domain)
    dkim_res = analyze_dkim(client, domain, selectors=selectors)
    dnssec_res = analyze_dnssec(client, domain)
    ns_res = analyze_nameservers(client, domain)
    mx_res = analyze_mx(client, domain)

    all_findings: list[Finding] = []
    all_findings.extend(spf_res.findings)
    all_findings.extend(dmarc_res.findings)
    all_findings.extend(dkim_res.findings)
    all_findings.extend(dnssec_res.findings)
    all_findings.extend(ns_res.findings)
    all_findings.extend(mx_res.findings)

    # Sort findings: highest severity first
    all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    score = calculate_score(all_findings)
    grade = determine_grade(score)
    timestamp = datetime.now(timezone.utc).isoformat()

    return AssessmentReport(
        domain=domain,
        timestamp=timestamp,
        score=score,
        grade=grade,
        spf=spf_res,
        dmarc=dmarc_res,
        dkim=dkim_res,
        dnssec=dnssec_res,
        nameservers=ns_res,
        mx=mx_res,
        all_findings=all_findings,
    )
