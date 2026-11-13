from __future__ import annotations
import re
from typing import TYPE_CHECKING

from dns_recon.models import Finding, SPFResult, Severity

if TYPE_CHECKING:
    from dns_recon.dns_client import DNSClient


# Mechanisms that trigger a DNS lookup under RFC 7208 Section 4.6.4
LOOKUP_MECHANISMS = ("include:", "a", "mx", "ptr", "exists:", "redirect=")


def _parse_spf_tokens(record: str) -> list[str]:
    """Split SPF record into tokens by whitespace."""
    return [token.strip() for token in record.split() if token.strip()]


def _count_lookups_recursive(
    client: DNSClient,
    domain: str,
    record: str,
    visited: set[str],
    max_depth: int = 5,
) -> tuple[int, list[str]]:
    """
    Recursively count lookups and collect includes, avoiding infinite loops.
    """
    tokens = _parse_spf_tokens(record)
    lookups = 0
    includes: list[str] = []

    for token in tokens:
        # Check lookup-triggering mechanisms
        lower = token.lower()
        if lower.startswith("include:"):
            target_domain = token.split(":", 1)[1].strip()
            lookups += 1
            includes.append(target_domain)
            if target_domain not in visited and len(visited) < 30 and max_depth > 0:
                visited.add(target_domain)
                nested_records = client.resolve_txt_records(target_domain)
                for nested_raw in nested_records:
                    if nested_raw.lower().startswith("v=spf1"):
                        nested_lookups, nested_includes = _count_lookups_recursive(
                            client, target_domain, nested_raw, visited, max_depth - 1
                        )
                        lookups += nested_lookups
                        includes.extend(nested_includes)
        elif lower.startswith("redirect="):
            target_domain = token.split("=", 1)[1].strip()
            lookups += 1
            if target_domain not in visited and len(visited) < 30 and max_depth > 0:
                visited.add(target_domain)
                nested_records = client.resolve_txt_records(target_domain)
                for nested_raw in nested_records:
                    if nested_raw.lower().startswith("v=spf1"):
                        nested_lookups, _ = _count_lookups_recursive(
                            client, target_domain, nested_raw, visited, max_depth - 1
                        )
                        lookups += nested_lookups
        elif (
            lower == "a"
            or lower.startswith("a:")
            or lower == "mx"
            or lower.startswith("mx:")
            or lower == "ptr"
            or lower.startswith("ptr:")
            or lower.startswith("exists:")
        ):
            lookups += 1

    return lookups, includes


def analyze_spf(client: DNSClient, domain: str) -> SPFResult:
    """Analyze SPF records for the given domain."""
    txt_records = client.resolve_txt_records(domain)
    spf_records = [r for r in txt_records if r.lower().startswith("v=spf1")]
    is_inherited = False
    inherited_from = ""

    # Subdomain apex fallback
    if not spf_records:
        labels = domain.split(".")
        for i in range(1, len(labels) - 1):
            parent_candidate = ".".join(labels[i:])
            parent_txt = client.resolve_txt_records(parent_candidate)
            parent_spf = [r for r in parent_txt if r.lower().startswith("v=spf1")]
            if parent_spf:
                spf_records = parent_spf
                is_inherited = True
                inherited_from = parent_candidate
                break

    findings: list[Finding] = []

    if not spf_records:
        findings.append(
            Finding(
                title="Missing SPF Record",
                severity=Severity.HIGH,
                description=f"Domain '{domain}' has no SPF record published.",
                remediation="Publish a valid TXT record starting with 'v=spf1' defining authorized sending IPs and ending with '-all'.",
            )
        )
        return SPFResult(is_valid=False, findings=findings)

    if len(spf_records) > 1:
        findings.append(
            Finding(
                title="Multiple SPF Records Detected",
                severity=Severity.CRITICAL,
                description=f"Domain '{domain}' publishes {len(spf_records)} SPF records. RFC 7208 §3.2 states that publishing multiple SPF records causes a PermError and invalidates SPF evaluation entirely.",
                remediation="Merge all SPF rules into a single TXT record.",
            )
        )
        return SPFResult(
            record=spf_records[0],
            is_valid=False,
            findings=findings,
        )

    primary_record = spf_records[0]
    tokens = _parse_spf_tokens(primary_record)

    # Find the 'all' mechanism
    all_mech: str | None = None
    for token in tokens:
        lower = token.lower()
        if lower in ("+all", "-all", "~all", "?all", "all"):
            all_mech = lower if lower.startswith(("+", "-", "~", "?")) else f"+{lower}"
            break

    # Evaluate all mechanism severity
    if all_mech == "+all":
        findings.append(
            Finding(
                title="Permissive SPF Mechanism (+all)",
                severity=Severity.CRITICAL,
                description="The SPF record explicitly permits any host on the internet to send email on behalf of this domain.",
                remediation="Change '+all' to '-all' to enforce strict sender authentication.",
            )
        )
    elif all_mech == "?all":
        findings.append(
            Finding(
                title="Permissive SPF Mechanism (?all)",
                severity=Severity.HIGH,
                description="The SPF record uses neutral (?all), which offers no spoofing protection as receiving servers treat it without policy enforcement.",
                remediation="Upgrade '?all' to '-all' (or '~all' temporarily during migration).",
            )
        )
    elif all_mech == "~all":
        findings.append(
            Finding(
                title="SPF Softfail (~all)",
                severity=Severity.MEDIUM,
                description="The SPF record uses softfail (~all). Unauthorized emails may still reach recipient inboxes (or spam folders) unless backed by an enforcing DMARC policy.",
                remediation="Once email senders are inventoried, transition from '~all' to '-all'.",
            )
        )
    elif all_mech == "-all":
        findings.append(
            Finding(
                title="Strict SPF Hardfail (-all)",
                severity=Severity.INFO,
                description="The SPF record enforces hardfail (-all), strictly blocking unauthorized senders.",
                remediation="Keep sender IP list up to date.",
            )
        )
    else:
        # Check if redirect is used
        has_redirect = any(t.lower().startswith("redirect=") for t in tokens)
        if not has_redirect:
            findings.append(
                Finding(
                    title="Missing SPF Fallback Mechanism",
                    severity=Severity.MEDIUM,
                    description="No default qualifier (like '-all' or '~all') or 'redirect' was found in the SPF record.",
                    remediation="Add '-all' at the end of the SPF record.",
                )
            )

    # Check DNS lookup limits
    visited = {domain}
    lookup_count, includes = _count_lookups_recursive(client, domain, primary_record, visited)

    if lookup_count > 10:
        findings.append(
            Finding(
                title="SPF Lookup Limit Exceeded (>10)",
                severity=Severity.HIGH,
                description=f"SPF record triggers {lookup_count} DNS lookups, exceeding the RFC 7208 maximum limit of 10. This causes mail servers to return a PermError.",
                remediation="Flatten your SPF record or use IP ranges directly instead of multiple nested includes.",
            )
        )

    return SPFResult(
        record=primary_record,
        is_valid=True,
        all_mechanism=all_mech,
        lookup_count=lookup_count,
        includes=includes,
        findings=findings,
    )

