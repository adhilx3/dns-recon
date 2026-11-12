from __future__ import annotations
from datetime import datetime, timezone

from dns_recon.dns_client import DNSClient
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

    # Clean domain input
    domain = domain.strip().lower().rstrip(".")

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
