from __future__ import annotations
from typing import TYPE_CHECKING

from dns_recon.models import Finding, Severity, SubdomainCNAMECheck, TakeoverResult

if TYPE_CHECKING:
    from dns_recon.dns_client import DNSClient

DEFAULT_SUBDOMAINS_TO_CHECK = [
    "www",
    "mail",
    "dev",
    "staging",
    "blog",
    "shop",
    "api",
    "support",
    "test",
    "cdn",
    "app",
    "status",
    "help",
    "docs",
    "autodiscover",
]

# Service fingerprints: match substring against CNAME target
KNOWN_SERVICES: dict[str, str] = {
    "github.io": "GitHub Pages",
    "github.com": "GitHub Pages",
    "s3.amazonaws.com": "AWS S3",
    "s3-website": "AWS S3 Static Website",
    "cloudfront.net": "AWS CloudFront",
    "herokuapp.com": "Heroku",
    "herokudns.com": "Heroku",
    "azurewebsites.net": "Microsoft Azure Web App",
    "cloudapp.net": "Microsoft Azure CloudApp",
    "blob.core.windows.net": "Azure Blob Storage",
    "trafficmanager.net": "Azure Traffic Manager",
    "myshopify.com": "Shopify",
    "zendesk.com": "Zendesk",
    "fastly.net": "Fastly CDN",
    "ghost.io": "Ghost Blog",
    "domains.tumblr.com": "Tumblr",
    "wordpress.com": "WordPress.com",
    "bitbucket.io": "Bitbucket Cloud",
    "surge.sh": "Surge.sh",
    "readme.io": "ReadMe.io",
    "cname.vercel-dns.com": "Vercel",
}


def identify_service(target: str) -> str | None:
    """Identify cloud/SaaS provider from CNAME target."""
    target_lower = target.lower()
    for pattern, service in KNOWN_SERVICES.items():
        if pattern in target_lower:
            return service
    return None


def analyze_takeover(
    client: DNSClient,
    domain: str,
    subdomains: list[str] | None = None,
) -> TakeoverResult:
    """
    Audit CNAME records for dangling targets and subdomain takeover risks.
    """
    subs_to_check = subdomains if subdomains is not None else DEFAULT_SUBDOMAINS_TO_CHECK
    all_targets = [f"{s}.{domain}" for s in subs_to_check]

    checked_subdomains: list[str] = []
    cname_checks: list[SubdomainCNAMECheck] = []
    findings: list[Finding] = []
    dangling_count = 0

    for full_host in all_targets:
        checked_subdomains.append(full_host)
        cname_target = client.resolve_cname(full_host)
        if not cname_target:
            continue

        service = identify_service(cname_target)
        target_exists = client.host_exists(cname_target)
        is_dangling = not target_exists

        check = SubdomainCNAMECheck(
            subdomain=full_host,
            cname_target=cname_target,
            service=service,
            is_dangling=is_dangling,
            target_exists=target_exists,
        )
        cname_checks.append(check)

        if is_dangling:
            dangling_count += 1
            if service:
                findings.append(
                    Finding(
                        title=f"Potential Subdomain Takeover ({service}): {full_host}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Host '{full_host}' points via CNAME to '{cname_target}' ({service}), "
                            "but the target does not resolve (NXDOMAIN). An adversary could register the "
                            f"abandoned resource on {service} to take control of this subdomain."
                        ),
                        remediation=(
                            f"Immediately remove the stale CNAME record pointing '{full_host}' to "
                            f"'{cname_target}', or recreate the resource on {service}."
                        ),
                    )
                )
            else:
                findings.append(
                    Finding(
                        title=f"Dangling CNAME Detected: {full_host}",
                        severity=Severity.HIGH,
                        description=(
                            f"Host '{full_host}' points via CNAME to '{cname_target}', which does not "
                            "resolve in DNS (NXDOMAIN). This creates a broken DNS pointer and potential hijacking vector."
                        ),
                        remediation=f"Remove or update the orphaned CNAME record for {full_host}.",
                    )
                )

    if not findings and cname_checks:
        findings.append(
            Finding(
                title="CNAME Records Verified Secure",
                severity=Severity.INFO,
                description=f"Verified {len(cname_checks)} CNAME record(s); all point to active, resolving targets.",
                remediation="Periodically audit decommissioned services to prevent dangling DNS records.",
            )
        )

    return TakeoverResult(
        checked_subdomains=checked_subdomains,
        cname_checks=cname_checks,
        dangling_count=dangling_count,
        findings=findings,
    )
