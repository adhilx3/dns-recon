from __future__ import annotations
import dns.resolver
import dns.zone
import dns.query
import dns.exception
import dns.rdatatype
import dns.reversename
from typing import Sequence

from dns_recon.models import RecordType


class DNSLookupError(Exception):
    """Raised when a critical DNS error occurs (e.g. NXDOMAIN)."""
    pass


class DNSClient:
    """DNS Client wrapper around dnspython with safe exception handling."""

    def __init__(
        self,
        nameservers: list[str] | None = None,
        timeout: float = 3.0,
        lifetime: float = 5.0,
    ) -> None:
        self.nameservers = nameservers
        self.timeout = timeout
        self.lifetime = lifetime
        self.resolver = dns.resolver.Resolver()
        if nameservers:
            self.resolver.nameservers = nameservers
        self.resolver.timeout = timeout
        self.resolver.lifetime = lifetime

    def domain_exists(self, domain: str) -> bool:
        """Check if the base domain exists (checks SOA or NS record)."""
        try:
            self.resolver.resolve(domain, "SOA")
            return True
        except dns.resolver.NXDOMAIN:
            return False
        except Exception:
            return True

    def query_records(self, domain: str, record_type: RecordType | str) -> list[str]:
        """Query DNS records for a domain. Returns list of record text strings."""
        rdtype_str = record_type.value if isinstance(record_type, RecordType) else str(record_type)
        try:
            answers = self.resolver.resolve(domain, rdtype_str)
            return [rdata.to_text() for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        except dns.exception.Timeout:
            return []
        except Exception:
            return []

    def resolve_txt_records(self, domain: str) -> list[str]:
        """Resolve TXT records and properly strip surrounding quotes and concatenate chunks."""
        raw_records = self.query_records(domain, RecordType.TXT)
        cleaned_records: list[str] = []
        for raw in raw_records:
            # dnspython TXT strings can be represented as "part1" "part2"
            # Strip outer quotes or joined quotes
            parts = [p.strip('"') for p in raw.split('" "')]
            full_text = "".join(parts).strip('"')
            cleaned_records.append(full_text)
        return cleaned_records

    def resolve_ips_for_name(self, name: str) -> list[str]:
        """Resolve A records for a hostname."""
        return self.query_records(name, RecordType.A)

    def resolve_aaaa(self, name: str) -> list[str]:
        """Resolve AAAA (IPv6) records for a hostname."""
        return self.query_records(name, RecordType.AAAA)

    def resolve_cname(self, name: str) -> str | None:
        """Query CNAME for a hostname. Returns target string without trailing dot or None."""
        records = self.query_records(name, RecordType.CNAME)
        if records:
            return records[0].strip().rstrip(".")
        return None

    def resolve_ptr(self, ip: str) -> list[str]:
        """Perform reverse DNS PTR lookup for an IP address."""
        try:
            rev_name = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(rev_name, "PTR")
            return [rdata.to_text().rstrip(".") for rdata in answers]
        except Exception:
            return []

    def host_exists(self, host: str) -> bool:
        """Check if a host exists by resolving A, AAAA, or CNAME."""
        for rtype in ("A", "AAAA", "CNAME"):
            try:
                ans = self.resolver.resolve(host, rtype)
                if len(ans) > 0:
                    return True
            except dns.resolver.NXDOMAIN:
                return False
            except Exception:
                continue
        return False

    def test_zone_transfer(self, domain: str, nameserver_host_or_ip: str) -> tuple[bool, list[str]]:
        """
        Safely test for open AXFR (DNS Zone Transfer) without causing disruption.
        Returns (vulnerable: bool, sample_records: list[str]).
        """
        target_ip = nameserver_host_or_ip
        # If hostname, try to resolve IP
        if not (target_ip.replace(".", "").isdigit() or ":" in target_ip):
            ips = self.resolve_ips_for_name(target_ip)
            if ips:
                target_ip = ips[0]
            else:
                return False, []

        try:
            # Attempt AXFR query with short timeout
            zone = dns.zone.from_xfr(dns.query.xfr(target_ip, domain, timeout=self.timeout, lifetime=self.lifetime))
            node_names = [str(node) for node in zone.nodes.keys()]
            return True, node_names
        except (
            dns.query.TransferError,
            dns.exception.FormError,
            dns.exception.Timeout,
            ConnectionRefusedError,
            ConnectionResetError,
            OSError,
            Exception,
        ):
            return False, []
