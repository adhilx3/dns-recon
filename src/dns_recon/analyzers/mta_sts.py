from __future__ import annotations
from typing import TYPE_CHECKING

from dns_recon.models import Finding, MTASTSResult, Severity

if TYPE_CHECKING:
    from dns_recon.dns_client import DNSClient


def parse_semicolon_tags(record: str) -> dict[str, str]:
    """Parse semicolon-delimited key=value tags."""
    tags: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def analyze_mta_sts(client: DNSClient, domain: str) -> MTASTSResult:
    """
    Inspect Mail Transfer Agent Strict Transport Security (MTA-STS, RFC 8461)
    and SMTP TLS Reporting (TLS-RPT, RFC 8460).
    """
    mta_sts_host = f"_mta-sts.{domain}"
    tls_rpt_host = f"_smtp._tls.{domain}"

    mta_sts_records = client.resolve_txt_records(mta_sts_host)
    tls_rpt_records = client.resolve_txt_records(tls_rpt_host)

    mta_sts_record: str | None = None
    for r in mta_sts_records:
        if r.lower().startswith("v=stsv1"):
            mta_sts_record = r
            break

    tls_rpt_record: str | None = None
    for r in tls_rpt_records:
        if r.lower().startswith("v=tlsrptv1"):
            tls_rpt_record = r
            break

    findings: list[Finding] = []
    has_mta_sts = False
    has_tls_rpt = False
    mta_sts_id: str | None = None
    tls_rpt_rua: list[str] = []

    # MTA-STS evaluation
    if not mta_sts_record:
        findings.append(
            Finding(
                title="MTA-STS Not Configured",
                severity=Severity.LOW,
                description=(
                    f"No MTA-STS record was found at {mta_sts_host}. Inbound mail delivery is "
                    "vulnerable to opportunistic TLS downgrade attacks (STARTTLS stripping) and man-in-the-middle tampering."
                ),
                remediation=(
                    "Implement MTA-STS by publishing a TXT record at _mta-sts."
                    f"{domain} (e.g. 'v=STSv1; id=20240101;') and hosting an HTTPS policy at https://mta-sts.{domain}/.well-known/mta-sts.txt."
                ),
            )
        )
    else:
        tags = parse_semicolon_tags(mta_sts_record)
        mta_sts_id = tags.get("id")
        if not mta_sts_id:
            findings.append(
                Finding(
                    title="MTA-STS Record Missing ID Tag",
                    severity=Severity.MEDIUM,
                    description="MTA-STS record is missing the required 'id=' policy version identifier.",
                    remediation="Add an id tag to the MTA-STS record (e.g., 'v=STSv1; id=20240101;').",
                )
            )
        else:
            has_mta_sts = True

    # TLS-RPT evaluation
    if not tls_rpt_record:
        findings.append(
            Finding(
                title="SMTP TLS Reporting (TLS-RPT) Not Configured",
                severity=Severity.LOW,
                description=(
                    f"No TLS-RPT record was found at {tls_rpt_host}. You will not receive diagnostic reports "
                    "when external mail servers experience TLS negotiation failures or certificate errors when sending to your domain."
                ),
                remediation=(
                    "Publish a TXT record at _smtp._tls."
                    f"{domain} with your reporting endpoint (e.g. 'v=TLSRPTv1; rua=mailto:tls-reports@{domain}')."
                ),
            )
        )
    else:
        tags = parse_semicolon_tags(tls_rpt_record)
        rua_val = tags.get("rua", "")
        if rua_val:
            tls_rpt_rua = [addr.strip() for addr in rua_val.split(",") if addr.strip()]
        if not tls_rpt_rua:
            findings.append(
                Finding(
                    title="TLS-RPT Missing Reporting Destination",
                    severity=Severity.LOW,
                    description="TLS-RPT record published but no reporting URI specified in rua= tag.",
                    remediation="Add an email address or HTTPS URI to rua= (e.g., 'rua=mailto:tls-reports@example.com').",
                )
            )
        else:
            has_tls_rpt = True

    if has_mta_sts and has_tls_rpt:
        findings.append(
            Finding(
                title="MTA-STS & TLS-RPT Active",
                severity=Severity.INFO,
                description="Strict transport security and TLS reporting are both active, safeguarding email transit against downgrade attacks.",
                remediation="Regularly review TLS-RPT reports to identify and rectify any TLS connectivity regressions.",
            )
        )

    return MTASTSResult(
        mta_sts_record=mta_sts_record,
        tls_rpt_record=tls_rpt_record,
        has_mta_sts=has_mta_sts,
        has_tls_rpt=has_tls_rpt,
        mta_sts_id=mta_sts_id,
        tls_rpt_rua=tls_rpt_rua,
        findings=findings,
    )
