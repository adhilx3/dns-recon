from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def penalty(self) -> int:
        penalties = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }
        return penalties[self]


class RecordType(str, Enum):
    A = "A"
    AAAA = "AAAA"
    MX = "MX"
    TXT = "TXT"
    NS = "NS"
    SOA = "SOA"
    CNAME = "CNAME"
    DNSKEY = "DNSKEY"
    DS = "DS"


@dataclass
class Finding:
    title: str
    severity: Severity
    description: str
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "remediation": self.remediation,
        }


@dataclass
class SPFResult:
    record: str | None = None
    is_valid: bool = False
    all_mechanism: str | None = None
    lookup_count: int = 0
    includes: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record": self.record,
            "is_valid": self.is_valid,
            "all_mechanism": self.all_mechanism,
            "lookup_count": self.lookup_count,
            "includes": self.includes,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class DMARCResult:
    record: str | None = None
    is_valid: bool = False
    policy: str | None = None
    subdomain_policy: str | None = None
    pct: int = 100
    rua: list[str] = field(default_factory=list)
    ruf: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record": self.record,
            "is_valid": self.is_valid,
            "policy": self.policy,
            "subdomain_policy": self.subdomain_policy,
            "pct": self.pct,
            "rua": self.rua,
            "ruf": self.ruf,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class DKIMSelectorResult:
    selector: str
    found: bool
    record: str | None = None
    key_size: int | None = None
    key_type: str | None = None


@dataclass
class DKIMResult:
    tested_selectors: list[str] = field(default_factory=list)
    found_selectors: list[DKIMSelectorResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tested_selectors": self.tested_selectors,
            "found_selectors": [asdict(s) for s in self.found_selectors],
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class DNSSECResult:
    has_dnskey: bool = False
    has_ds: bool = False
    is_enabled: bool = False
    dnskey_count: int = 0
    ds_count: int = 0
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "has_dnskey": self.has_dnskey,
            "has_ds": self.has_ds,
            "is_enabled": self.is_enabled,
            "dnskey_count": self.dnskey_count,
            "ds_count": self.ds_count,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class AXFRCheckResult:
    nameserver: str
    nameserver_ip: str | None
    vulnerable: bool
    record_count: int = 0
    error: str | None = None


@dataclass
class NameserverResult:
    nameservers: list[str] = field(default_factory=list)
    axfr_checks: list[AXFRCheckResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "nameservers": self.nameservers,
            "axfr_checks": [asdict(c) for c in self.axfr_checks],
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class MXRecordInfo:
    exchange: str
    preference: int


@dataclass
class MXResult:
    records: list[MXRecordInfo] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "records": [asdict(r) for r in self.records],
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class BIMIResult:
    record: str | None = None
    is_valid: bool = False
    version: str | None = None
    location: str | None = None
    authority: str | None = None
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record": self.record,
            "is_valid": self.is_valid,
            "version": self.version,
            "location": self.location,
            "authority": self.authority,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class MTASTSResult:
    mta_sts_record: str | None = None
    tls_rpt_record: str | None = None
    has_mta_sts: bool = False
    has_tls_rpt: bool = False
    mta_sts_mode: str | None = None
    mta_sts_id: str | None = None
    tls_rpt_rua: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mta_sts_record": self.mta_sts_record,
            "tls_rpt_record": self.tls_rpt_record,
            "has_mta_sts": self.has_mta_sts,
            "has_tls_rpt": self.has_tls_rpt,
            "mta_sts_mode": self.mta_sts_mode,
            "mta_sts_id": self.mta_sts_id,
            "tls_rpt_rua": self.tls_rpt_rua,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class SubdomainCNAMECheck:
    subdomain: str
    cname_target: str
    service: str | None = None
    is_dangling: bool = False
    target_exists: bool = True
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TakeoverResult:
    checked_subdomains: list[str] = field(default_factory=list)
    cname_checks: list[SubdomainCNAMECheck] = field(default_factory=list)
    dangling_count: int = 0
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "checked_subdomains": self.checked_subdomains,
            "cname_checks": [c.to_dict() for c in self.cname_checks],
            "dangling_count": self.dangling_count,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class IPRecord:
    ip: str
    version: str
    ptr: str | None = None
    provider: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SubdomainRecord:
    subdomain: str
    record_type: str
    target: str
    is_live: bool = True
    source: str = "dns"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InfoGatherResult:
    domain: str
    timestamp: str
    ips: list[IPRecord] = field(default_factory=list)
    canonical_name: str | None = None
    nameservers: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)
    subdomains: list[SubdomainRecord] = field(default_factory=list)
    detected_host: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "timestamp": self.timestamp,
            "ips": [ip.to_dict() for ip in self.ips],
            "canonical_name": self.canonical_name,
            "nameservers": self.nameservers,
            "mx_records": self.mx_records,
            "subdomains": [s.to_dict() for s in self.subdomains],
            "detected_host": self.detected_host,
        }


@dataclass
class AssessmentReport:
    domain: str
    timestamp: str
    score: int
    grade: str
    spf: SPFResult
    dmarc: DMARCResult
    dkim: DKIMResult
    dnssec: DNSSECResult
    nameservers: NameserverResult
    mx: MXResult
    bimi: BIMIResult = field(default_factory=BIMIResult)
    mta_sts: MTASTSResult = field(default_factory=MTASTSResult)
    takeover: TakeoverResult = field(default_factory=TakeoverResult)
    all_findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "timestamp": self.timestamp,
            "score": self.score,
            "grade": self.grade,
            "spf": self.spf.to_dict(),
            "dmarc": self.dmarc.to_dict(),
            "dkim": self.dkim.to_dict(),
            "dnssec": self.dnssec.to_dict(),
            "nameservers": self.nameservers.to_dict(),
            "mx": self.mx.to_dict(),
            "bimi": self.bimi.to_dict(),
            "mta_sts": self.mta_sts.to_dict(),
            "takeover": self.takeover.to_dict(),
            "all_findings": [f.to_dict() for f in self.all_findings],
        }

