from __future__ import annotations
from typing import TYPE_CHECKING

from dns_recon.models import BIMIResult, Finding, Severity

if TYPE_CHECKING:
    from dns_recon.dns_client import DNSClient


def parse_bimi_tags(record: str) -> dict[str, str]:
    """Parse semicolon-delimited BIMI tags into a lowercase key dictionary."""
    tags: dict[str, str] = {}
    parts = record.split(";")
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            key, val = part.split("=", 1)
            tags[key.strip().lower()] = val.strip()
    return tags


def analyze_bimi(
    client: DNSClient,
    domain: str,
    selector: str = "default",
) -> BIMIResult:
    """
    Inspect BIMI (Brand Indicators for Message Identification) record.
    Queries: <selector>._bimi.<domain>
    """
    bimi_domain = f"{selector}._bimi.{domain}"
    txt_records = client.resolve_txt_records(bimi_domain)

    bimi_record: str | None = None
    for record in txt_records:
        if record.lower().startswith("v=bimi1"):
            bimi_record = record
            break

    findings: list[Finding] = []

    if not bimi_record:
        findings.append(
            Finding(
                title="BIMI Record Not Published",
                severity=Severity.INFO,
                description=f"No BIMI record was found at {bimi_domain}.",
                remediation=(
                    "Publish a BIMI TXT record with an SVG logo indicator to display your verified "
                    "brand logo next to authenticated emails in supported clients (Gmail, Apple Mail, Yahoo)."
                ),
            )
        )
        return BIMIResult(record=None, is_valid=False, findings=findings)

    tags = parse_bimi_tags(bimi_record)
    version = tags.get("v")
    location = tags.get("l")
    authority = tags.get("a")

    if not version or version.upper() != "BIMI1":
        findings.append(
            Finding(
                title="Invalid BIMI Version Tag",
                severity=Severity.MEDIUM,
                description=f"BIMI record found but does not specify a valid version (found: {version}).",
                remediation="Ensure the BIMI record starts with 'v=BIMI1;'.",
            )
        )
        return BIMIResult(
            record=bimi_record,
            is_valid=False,
            version=version,
            location=location,
            authority=authority,
            findings=findings,
        )

    # Validate SVG location URL
    is_valid = True
    if not location:
        is_valid = False
        findings.append(
            Finding(
                title="BIMI Indicator URL Missing",
                severity=Severity.MEDIUM,
                description="BIMI record specifies no logo indicator URL (l= tag is missing or empty).",
                remediation="Provide an HTTPS URL to an SVG Tiny PS format logo (e.g., l=https://example.com/logo.svg).",
            )
        )
    elif not location.lower().startswith("https://"):
        is_valid = False
        findings.append(
            Finding(
                title="Insecure BIMI Indicator URL",
                severity=Severity.MEDIUM,
                description=f"BIMI logo indicator must use HTTPS (found: {location}).",
                remediation="Update the logo URL in the l= tag to use a secure HTTPS endpoint.",
            )
        )

    # Authority / VMC certificate check
    if not authority or authority.lower() == "":
        findings.append(
            Finding(
                title="BIMI VMC Certificate Not Configured",
                severity=Severity.INFO,
                description="No Verified Mark Certificate (a= tag) was specified. While optional in the RFC, major providers (Gmail, Apple Mail) require a VMC to display logos.",
                remediation="Acquire a Verified Mark Certificate (VMC) and reference it with a=https://example.com/cert.pem for universal mailbox support.",
            )
        )
    elif not authority.lower().startswith("https://"):
        findings.append(
            Finding(
                title="Insecure BIMI Authority Certificate URL",
                severity=Severity.LOW,
                description=f"BIMI authority URL (a=) should use HTTPS (found: {authority}).",
                remediation="Ensure the certificate authority link in the a= tag uses HTTPS.",
            )
        )

    if is_valid and not any(f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM) for f in findings):
        findings.append(
            Finding(
                title="BIMI Record Published",
                severity=Severity.INFO,
                description=f"Valid BIMI record published with logo indicator: {location}",
                remediation="Keep certificate and SVG logo updated and ensure DMARC policy remains at p=reject or quarantine.",
            )
        )

    return BIMIResult(
        record=bimi_record,
        is_valid=is_valid,
        version=version,
        location=location,
        authority=authority,
        findings=findings,
    )
