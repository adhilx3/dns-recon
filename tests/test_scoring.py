from unittest.mock import MagicMock
import pytest

from dns_recon.models import (
    AssessmentReport,
    DKIMResult,
    DNSSECResult,
    Finding,
    MXResult,
    NameserverResult,
    SPFResult,
    DMARCResult,
    Severity,
)
from dns_recon.scoring import calculate_score, determine_grade, normalize_domain, run_full_assessment


def test_normalize_domain():
    assert normalize_domain("adhilparokkot.vercel.app/admin") == "adhilparokkot.vercel.app"
    assert normalize_domain("https://example.com/some/path?param=1") == "example.com"
    assert normalize_domain("http://sub.domain.com:8080/test") == "sub.domain.com"
    assert normalize_domain("  TEST.ORG/  ") == "test.org"
    assert normalize_domain("domain.co.uk.") == "domain.co.uk"


def test_calculate_score_clean():
    findings = [
        Finding(title="SPF Hardfail", severity=Severity.INFO, description="", remediation=""),
        Finding(title="DMARC Reject", severity=Severity.INFO, description="", remediation=""),
    ]
    score = calculate_score(findings)
    assert score == 100
    assert determine_grade(score) == "A+"


def test_calculate_score_with_penalties():
    findings = [
        Finding(title="No DMARC", severity=Severity.CRITICAL, description="", remediation=""),  # -25
        Finding(title="Permissive SPF", severity=Severity.HIGH, description="", remediation=""),  # -15
        Finding(title="No DNSSEC", severity=Severity.MEDIUM, description="", remediation=""),  # -8
        Finding(title="Missing RUA", severity=Severity.LOW, description="", remediation=""),  # -3
    ]
    # Total deduction: 25 + 15 + 8 + 3 = 51 -> Score: 49
    score = calculate_score(findings)
    assert score == 49
    assert determine_grade(score) == "D"


def test_calculate_score_zero_floor():
    findings = [
        Finding(title=f"Crit {i}", severity=Severity.CRITICAL, description="", remediation="")
        for i in range(10)
    ]
    score = calculate_score(findings)
    assert score == 0
    assert determine_grade(score) == "F"


def test_run_full_assessment_mocked():
    mock_client = MagicMock()
    mock_client.domain_exists.return_value = True
    # Mock SPF
    mock_client.resolve_txt_records.side_effect = lambda domain: (
        ["v=spf1 -all"] if domain == "example.com"
        else ["v=DMARC1; p=reject; rua=mailto:d@example.com"] if domain == "_dmarc.example.com"
        else []
    )
    # Mock records for DNSSEC, NS, MX
    def mock_query(domain, rtype):
        from dns_recon.models import RecordType
        if rtype == RecordType.DNSKEY:
            return ["257 3 13 key"]
        if rtype == RecordType.DS:
            return ["2371 13 2 ds"]
        if rtype == RecordType.NS:
            return ["ns1.example.com.", "ns2.example.com."]
        if rtype == RecordType.MX:
            return ["10 mail.example.com."]
        return []

    mock_client.query_records.side_effect = mock_query
    mock_client.resolve_ips_for_name.return_value = ["192.0.2.1"]
    mock_client.test_zone_transfer.return_value = (False, [])

    report = run_full_assessment("example.com", client=mock_client)
    assert report.domain == "example.com"
    assert report.score >= 90
    assert report.grade in ("A+", "A")
    assert report.spf.is_valid is True
    assert report.dmarc.policy == "reject"
    assert report.dnssec.is_enabled is True
    assert len(report.nameservers.nameservers) == 2


def test_subdomain_apex_inheritance():
    mock_client = MagicMock()
    mock_client.domain_exists.return_value = True
    # Child sub.example.com has no SPF/DMARC, apex example.com has strict SPF and DMARC reject
    def mock_resolve_txt(domain):
        if domain == "example.com":
            return ["v=spf1 -all"]
        if domain == "_dmarc.example.com":
            return ["v=DMARC1; p=reject; sp=reject;"]
        return []

    def mock_query(domain, rtype):
        from dns_recon.models import RecordType
        if rtype == RecordType.NS and domain == "example.com":
            return ["ns1.example.com.", "ns2.example.com."]
        return []

    mock_client.resolve_txt_records.side_effect = mock_resolve_txt
    mock_client.query_records.side_effect = mock_query
    mock_client.resolve_ips_for_name.return_value = ["192.0.2.1"]
    mock_client.test_zone_transfer.return_value = (False, [])

    report = run_full_assessment("sub.example.com", client=mock_client)
    assert report.score >= 85
    assert report.grade in ("A+", "A")
    assert report.spf.is_valid is True
    assert report.spf.all_mechanism == "-all"
    assert report.dmarc.policy == "reject"
    assert len(report.nameservers.nameservers) == 2

