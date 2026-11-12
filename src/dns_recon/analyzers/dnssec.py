from __future__ import annotations
from typing import TYPE_CHECKING

from dns_recon.models import DNSSECResult, Finding, RecordType, Severity

if TYPE_CHECKING:
    from dns_recon.dns_client import DNSClient


def analyze_dnssec(client: DNSClient, domain: str) -> DNSSECResult:
    """Analyze DNSSEC deployment for domain."""
    dnskey_records = client.query_records(domain, RecordType.DNSKEY)
    ds_records = client.query_records(domain, RecordType.DS)

    has_dnskey = len(dnskey_records) > 0
    has_ds = len(ds_records) > 0
    is_enabled = has_dnskey and has_ds

    findings: list[Finding] = []

    if not has_dnskey and not has_ds:
        findings.append(
            Finding(
                title="DNSSEC Not Enabled",
                severity=Severity.MEDIUM,
                description=f"Neither DNSKEY nor DS records exist for '{domain}'. DNS responses are not cryptographically signed, leaving visitors vulnerable to DNS spoofing and cache poisoning (MitM attacks).",
                remediation="Enable DNSSEC in your authoritative DNS provider and configure the DS record at your domain registrar.",
            )
        )
    elif has_dnskey and not has_ds:
        findings.append(
            Finding(
                title="Incomplete DNSSEC Configuration (Missing DS at Registrar)",
                severity=Severity.HIGH,
                description=f"Domain '{domain}' publishes DNSKEY records, but no DS records were found at the parent zone. DNSSEC validation chain of trust is broken.",
                remediation="Add the DS delegation signer record to your domain registrar.",
            )
        )
    elif has_ds and not has_dnskey:
        findings.append(
            Finding(
                title="Broken DNSSEC Configuration (DS present without DNSKEY)",
                severity=Severity.CRITICAL,
                description=f"Parent zone has DS records pointing to '{domain}', but the zone itself lacks corresponding DNSKEY records. Validating resolvers will fail to resolve the domain (Bogus state).",
                remediation="Publish the required DNSKEY records or remove the stale DS records from the registrar.",
            )
        )
    else:
        findings.append(
            Finding(
                title="DNSSEC Configured and Validated",
                severity=Severity.INFO,
                description=f"Domain '{domain}' has {len(dnskey_records)} DNSKEY records and {len(ds_records)} DS records, maintaining a valid chain of trust.",
                remediation="Ensure automated DNSSEC key rollover is active.",
            )
        )

    return DNSSECResult(
        has_dnskey=has_dnskey,
        has_ds=has_ds,
        is_enabled=is_enabled,
        dnskey_count=len(dnskey_records),
        ds_count=len(ds_records),
        findings=findings,
    )

