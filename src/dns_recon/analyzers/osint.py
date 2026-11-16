from __future__ import annotations
from datetime import datetime, timezone
import json
from typing import TYPE_CHECKING
import urllib.request
import urllib.error

from dns_recon.models import InfoGatherResult, IPRecord, SubdomainRecord

if TYPE_CHECKING:
    from dns_recon.dns_client import DNSClient

COMMON_OSINT_SUBDOMAINS = [
    "www",
    "mail",
    "blog",
    "dev",
    "api",
    "app",
    "shop",
    "cdn",
    "status",
    "portal",
    "support",
    "test",
    "admin",
    "auth",
    "login",
    "secure",
    "vpn",
    "remote",
    "webmail",
    "server",
    "staging",
    "beta",
    "assets",
    "docs",
    "help",
    "billing",
    "cloud",
    "mx",
]

PROVIDER_PATTERNS = [
    ("cloudflare", "Cloudflare CDN & Edge"),
    ("vercel", "Vercel"),
    ("amazonaws", "Amazon Web Services (AWS)"),
    ("cloudfront", "Amazon CloudFront"),
    ("google", "Google Cloud"),
    ("1e100", "Google Infrastructure"),
    ("azure", "Microsoft Azure"),
    ("fastly", "Fastly Edge Cloud"),
    ("akamai", "Akamai CDN"),
    ("digitalocean", "DigitalOcean"),
    ("hetzner", "Hetzner Online"),
    ("ovh", "OVHcloud"),
    ("linode", "Linode / Akamai"),
    ("github", "GitHub"),
]


def detect_provider(text_to_check: str) -> str | None:
    """Detect cloud/CDN provider from reverse PTR hostname or CNAME."""
    lower = text_to_check.lower()
    for pattern, name in PROVIDER_PATTERNS:
        if pattern in lower:
            return name
    return None


def fetch_crt_sh_subdomains(domain: str, timeout: float = 3.5) -> set[str]:
    """
    Fetch historical and active subdomains from Certificate Transparency logs via crt.sh.
    Gracefully returns empty set if request times out or crt.sh is unreachable.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (compatible; DNSReconOSINT/2.0)"},
    )
    discovered: set[str] = set()

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8", errors="ignore"))
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for raw_name in name_value.split("\n"):
                        clean_name = raw_name.strip().lower().lstrip("*.")
                        if clean_name.endswith(f".{domain}") or clean_name == domain:
                            discovered.add(clean_name)
    except Exception:
        # Graceful fallback: CT log service unreachable or rate-limited
        pass

    return discovered


def gather_information(
    client: DNSClient,
    domain: str,
    fetch_ct_logs: bool = True,
    max_subdomain_probes: int = 40,
) -> InfoGatherResult:
    """
    Conduct comprehensive reconnaissance and OSINT:
    - Target IPv4 (A) & IPv6 (AAAA) resolution
    - Reverse DNS PTR records
    - CDN / Hosting provider detection
    - Infrastructure nameservers and MX records
    - Subdomain discovery via CT logs + common DNS permutations
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    ip_records: list[IPRecord] = []
    detected_host: str | None = None

    # Check root and www CNAME
    cname_target = client.resolve_cname(domain)
    if not cname_target:
        cname_target = client.resolve_cname(f"www.{domain}")
    if cname_target:
        detected_host = detect_provider(cname_target)

    # 1. Resolve IPv4 & IPv6 for root domain
    ipv4s = client.resolve_ips_for_name(domain)
    ipv6s = client.resolve_aaaa(domain)

    # If root domain has no A, try www
    if not ipv4s and not ipv6s:
        ipv4s = client.resolve_ips_for_name(f"www.{domain}")

    for ip in ipv4s:
        ptrs = client.resolve_ptr(ip)
        ptr_val = ptrs[0] if ptrs else None
        prov = detect_provider(ptr_val or "") if ptr_val else None
        if prov and not detected_host:
            detected_host = prov
        ip_records.append(
            IPRecord(
                ip=ip,
                version="IPv4",
                ptr=ptr_val,
                provider=prov,
            )
        )

    for ip in ipv6s:
        ptrs = client.resolve_ptr(ip)
        ptr_val = ptrs[0] if ptrs else None
        prov = detect_provider(ptr_val or "") if ptr_val else None
        if prov and not detected_host:
            detected_host = prov
        ip_records.append(
            IPRecord(
                ip=ip,
                version="IPv6",
                ptr=ptr_val,
                provider=prov,
            )
        )

    # 2. Infrastructure Nameservers & MX
    ns_records = [ns.rstrip(".") for ns in client.query_records(domain, "NS")]
    mx_records = [mx.strip() for mx in client.query_records(domain, "MX")]

    # If provider still not detected, check NS
    if not detected_host and ns_records:
        for ns in ns_records:
            detected_host = detect_provider(ns)
            if detected_host:
                break

    # 3. Subdomain Enumeration
    discovered_names: set[str] = set()

    # Built-in common wordlist
    for prefix in COMMON_OSINT_SUBDOMAINS:
        discovered_names.add(f"{prefix}.{domain}")

    # Certificate Transparency logs
    if fetch_ct_logs:
        ct_subdomains = fetch_crt_sh_subdomains(domain)
        discovered_names.update(ct_subdomains)

    # Sort subdomains: www first, then alphabetical
    def sort_key(name: str) -> tuple[int, str]:
        if name == f"www.{domain}":
            return (0, name)
        return (1, name)

    candidates = sorted(discovered_names, key=sort_key)[:max_subdomain_probes]

    subdomain_records: list[SubdomainRecord] = []
    for sub in candidates:
        # Check CNAME first
        cname = client.resolve_cname(sub)
        if cname:
            subdomain_records.append(
                SubdomainRecord(
                    subdomain=sub,
                    record_type="CNAME",
                    target=cname,
                    is_live=True,
                    source="ct_logs" if fetch_ct_logs else "dns",
                )
            )
            continue

        # Check A record
        ips = client.resolve_ips_for_name(sub)
        if ips:
            subdomain_records.append(
                SubdomainRecord(
                    subdomain=sub,
                    record_type="A",
                    target=ips[0],
                    is_live=True,
                    source="ct_logs" if fetch_ct_logs else "dns",
                )
            )
        else:
            # Check AAAA
            aaaa_ips = client.resolve_aaaa(sub)
            if aaaa_ips:
                subdomain_records.append(
                    SubdomainRecord(
                        subdomain=sub,
                        record_type="AAAA",
                        target=aaaa_ips[0],
                        is_live=True,
                        source="ct_logs" if fetch_ct_logs else "dns",
                    )
                )
            else:
                # Discovered from wordlist or CT logs, but currently inactive
                subdomain_records.append(
                    SubdomainRecord(
                        subdomain=sub,
                        record_type="-",
                        target="No Active IP",
                        is_live=False,
                        source="ct_logs" if fetch_ct_logs else "dns",
                    )
                )

    return InfoGatherResult(
        domain=domain,
        timestamp=timestamp,
        ips=ip_records,
        canonical_name=cname_target,
        nameservers=ns_records,
        mx_records=mx_records,
        subdomains=subdomain_records,
        detected_host=detected_host,
    )
