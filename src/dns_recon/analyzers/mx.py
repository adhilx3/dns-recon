from __future__ import annotations
from typing import TYPE_CHECKING

from dns_recon.models import Finding, MXRecordInfo, MXResult, RecordType, Severity

if TYPE_CHECKING:
    from dns_recon.dns_client import DNSClient


def analyze_mx(client: DNSClient, domain: str) -> MXResult:
    """Analyze MX records for the domain."""
    raw_mx = client.query_records(domain, RecordType.MX)
    records: list[MXRecordInfo] = []
    findings: list[Finding] = []

    for item in raw_mx:
        parts = item.split()
        if len(parts) >= 2:
            try:
                pref = int(parts[0])
                exchange = parts[1]
                records.append(MXRecordInfo(exchange=exchange, preference=pref))
            except ValueError:
                continue

    # Sort by preference ascending
    records.sort(key=lambda r: r.preference)

    if not records:
        findings.append(
            Finding(
                title="No MX Records Configured (Non-Receiving Domain)",
                severity=Severity.INFO,
                description=f"Domain '{domain}' does not publish any MX records (designated non-receiving domain).",
                remediation="If this domain is meant to receive incoming emails, configure dedicated MX records with proper priority.",
            )
        )
    else:
        findings.append(
            Finding(
                title=f"{len(records)} MX Record(s) Configured",
                severity=Severity.INFO,
                description=f"Found {len(records)} mail exchange server(s): {', '.join([r.exchange for r in records])}.",
                remediation="Ensure mail servers support opportunistic TLS (STARTTLS).",
            )
        )

    return MXResult(records=records, findings=findings)

