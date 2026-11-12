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
            "all_findings": [f.to_dict() for f in self.all_findings],
        }
