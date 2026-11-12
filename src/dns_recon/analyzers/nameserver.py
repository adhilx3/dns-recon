from __future__ import annotations
from typing import TYPE_CHECKING

from dns_recon.models import AXFRCheckResult, Finding, NameserverResult, RecordType, Severity

if TYPE_CHECKING:
    from dns_recon.dns_client import DNSClient


def analyze_nameservers(client: DNSClient, domain: str) -> NameserverResult:
    """Analyze nameserver redundancy and test for open zone transfers (AXFR)."""
    raw_ns = client.query_records(domain, RecordType.NS)
    nameservers = [ns.rstrip(".") for ns in raw_ns]

    findings: list[Finding] = []
    axfr_checks: list[AXFRCheckResult] = []

    if not nameservers:
        findings.append(
            Finding(
                title="No Authoritative Nameservers Found",
                severity=Severity.CRITICAL,
                description=f"Domain '{domain}' has no NS records returned. DNS queries cannot be authoritatively resolved.",
                remediation="Configure at least two authoritative nameservers at your domain registrar.",
            )
        )
        return NameserverResult(nameservers=[], axfr_checks=[], findings=findings)

    if len(nameservers) < 2:
        findings.append(
            Finding(
                title="Insufficient Nameserver Redundancy",
                severity=Severity.HIGH,
                description=f"Only {len(nameservers)} nameserver ({nameservers[0]}) is configured. RFC 2182 requires at least two geographically and topologically diverse nameservers to prevent a single point of failure (SPOF).",
                remediation="Deploy a secondary nameserver on an independent network/autonomous system (AS).",
            )
        )

    for ns in nameservers:
        ips = client.resolve_ips_for_name(ns)
        ip = ips[0] if ips else None
        is_vuln, records = client.test_zone_transfer(domain, ns)

        axfr_checks.append(
            AXFRCheckResult(
                nameserver=ns,
                nameserver_ip=ip,
                vulnerable=is_vuln,
                record_count=len(records),
            )
        )

        if is_vuln:
            findings.append(
                Finding(
                    title=f"Open DNS Zone Transfer (AXFR) on {ns}",
                    severity=Severity.CRITICAL,
                    description=f"Nameserver '{ns}' ({ip or 'unknown IP'}) permits unrestricted AXFR zone transfers. Any attacker can download your complete DNS database, revealing hidden internal subdomains, dev portals, and infrastructure IPs.",
                    remediation="Configure your nameserver (BIND, NSD, PowerDNS, etc.) to restrict AXFR transfers only to trusted secondary IP addresses.",
                )
            )

    if not any(c.vulnerable for c in axfr_checks):
        findings.append(
            Finding(
                title="DNS Zone Transfers (AXFR) Denied",
                severity=Severity.INFO,
                description="All tested authoritative nameservers properly refused unauthorized zone transfers.",
                remediation="Maintain existing access control lists (ACLs).",
            )
        )

    return NameserverResult(
        nameservers=nameservers,
        axfr_checks=axfr_checks,
        findings=findings,
    )
