from __future__ import annotations
from typing import TYPE_CHECKING

from dns_recon.models import DMARCResult, Finding, Severity

if TYPE_CHECKING:
    from dns_recon.dns_client import DNSClient


def _parse_dmarc_tags(record: str) -> dict[str, str]:
    """Parse tag=value pairs separated by semicolons."""
    tags: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            key, val = part.split("=", 1)
            tags[key.strip().lower()] = val.strip()
    return tags


def analyze_dmarc(client: DNSClient, domain: str) -> DMARCResult:
    """Analyze DMARC record for the target domain (with RFC 7489 subdomain inheritance)."""
    labels = domain.split(".")
    target_domain = domain
    dmarc_records: list[str] = []
    is_inherited = False
    inherited_from = ""

    # RFC 7489 §6.6.3 Policy Discovery: query domain, then walk up labels to find org domain DMARC
    for i in range(len(labels) - 1):
        curr_domain = ".".join(labels[i:])
        dmarc_host = f"_dmarc.{curr_domain}"
        txt_records = client.resolve_txt_records(dmarc_host)
        matching = [r for r in txt_records if r.lower().startswith("v=dmarc1")]
        if matching:
            dmarc_records = matching
            target_domain = curr_domain
            if i > 0:
                is_inherited = True
                inherited_from = curr_domain
            break

    findings: list[Finding] = []

    if not dmarc_records:
        findings.append(
            Finding(
                title="Missing DMARC Record",
                severity=Severity.CRITICAL,
                description=f"No DMARC record found at '_dmarc.{domain}'. Anyone can send emails spoofing @{domain} without being rejected or quarantined.",
                remediation="Publish a DMARC record (e.g. 'v=DMARC1; p=reject; rua=mailto:dmarc-reports@yourdomain.com') to enforce authentication.",
            )
        )
        return DMARCResult(is_valid=False, findings=findings)

    if len(dmarc_records) > 1:
        findings.append(
            Finding(
                title="Multiple DMARC Records Detected",
                severity=Severity.CRITICAL,
                description=f"Domain publishes {len(dmarc_records)} DMARC records at '_dmarc.{target_domain}'. RFC 7489 Section 6.6.3 dictates that receiving MTAs must treat multiple DMARC records as an invalid configuration and ignore DMARC entirely.",
                remediation="Remove the extra DMARC TXT record so only a single authoritative record remains.",
            )
        )
        return DMARCResult(record=dmarc_records[0], is_valid=False, findings=findings)

    primary_record = dmarc_records[0]
    tags = _parse_dmarc_tags(primary_record)

    policy = tags.get("p", "").lower()
    subdomain_policy = tags.get("sp", "").lower() if "sp" in tags else None

    # Under RFC 7489, if inherited, subdomain policy 'sp' takes precedence if present; otherwise 'p'
    effective_policy = subdomain_policy if (is_inherited and subdomain_policy) else policy

    # Percentage
    pct = 100
    if "pct" in tags:
        try:
            pct = int(tags["pct"])
        except ValueError:
            pct = 100

    # Reporting URIs
    rua = [u.strip() for u in tags.get("rua", "").split(",") if u.strip()]
    ruf = [u.strip() for u in tags.get("ruf", "").split(",") if u.strip()]

    # Policy evaluations
    if effective_policy == "none":
        findings.append(
            Finding(
                title="DMARC Policy Set to 'none': Monitoring Only",
                severity=Severity.HIGH,
                description=f"The DMARC policy{f' (inherited from {inherited_from})' if is_inherited else ''} is set to 'p=none'. While reports are generated, unauthorized/spoofed emails will NOT be blocked or quarantined by receiving mail servers.",
                remediation="Analyze aggregate reports (rua) to ensure legitimate email streams pass SPF/DKIM, then upgrade policy to 'p=quarantine' or 'p=reject'.",
            )
        )
    elif effective_policy == "quarantine":
        findings.append(
            Finding(
                title="DMARC Policy 'quarantine': Partial Protection",
                severity=Severity.MEDIUM,
                description=f"The DMARC policy{f' (inherited from {inherited_from})' if is_inherited else ''} is set to 'quarantine'. Failed emails are routed to spam/junk folders instead of being rejected.",
                remediation="Transition to 'p=reject' once all authorized senders are verified.",
            )
        )
    elif effective_policy == "reject":
        findings.append(
            Finding(
                title="DMARC Policy 'reject': Strong Anti-Spoofing Protection",
                severity=Severity.INFO,
                description=f"Domain strictly rejects unauthenticated emails{f' (enforced via RFC 7489 policy inherited from {inherited_from})' if is_inherited else ''}, providing full anti-spoofing defense.",
                remediation="Maintain alignment between envelope sender and header From domain.",
            )
        )
    else:
        findings.append(
            Finding(
                title="Invalid or Missing DMARC Policy Tag (p=)",
                severity=Severity.CRITICAL,
                description="The required 'p=' policy tag is missing or invalid in the DMARC record.",
                remediation="Specify a valid policy: 'p=none', 'p=quarantine', or 'p=reject'.",
            )
        )

    # Subdomain policy check (only if evaluating the apex domain directly)
    if not is_inherited and subdomain_policy == "none" and policy in ("quarantine", "reject"):
        findings.append(
            Finding(
                title="Permissive Subdomain DMARC Policy (sp=none)",
                severity=Severity.HIGH,
                description="While the main domain is protected, subdomains have policy set to 'sp=none', allowing attackers to spoof subdomains like 'mail.domain.com' or 'auth.domain.com'.",
                remediation="Remove 'sp=none' or explicitly set 'sp=reject' to protect all subdomains.",
            )
        )

    # Incomplete percentage enforcement
    if pct < 100:
        findings.append(
            Finding(
                title="DMARC Incomplete Enforcement (pct < 100)",
                severity=Severity.MEDIUM,
                description=f"DMARC policy applies only to {pct}% of messages. The remaining {100 - pct}% fall back to the next less strict policy.",
                remediation="Increase 'pct=100' for comprehensive enforcement across all incoming mail.",
            )
        )

    # Missing reporting tags (only warn if this is an apex domain managing its own reports)
    if not rua and not is_inherited:
        findings.append(
            Finding(
                title="Missing DMARC Aggregate Reporting (rua)",
                severity=Severity.LOW,
                description="No aggregate reporting email ('rua=') is defined. The domain owner cannot see who is sending emails on their behalf or identify spoofing attempts.",
                remediation="Add 'rua=mailto:dmarc-reports@yourdomain.com' to receive daily XML reports.",
            )
        )

    return DMARCResult(
        record=primary_record,
        is_valid=True,
        policy=effective_policy,
        subdomain_policy=subdomain_policy,
        pct=pct,
        rua=rua,
        ruf=ruf,
        findings=findings,
    )

