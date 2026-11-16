import json
from unittest.mock import MagicMock, patch
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
from dns_recon.formatters import format_json, format_markdown
from dns_recon.cli import main


@pytest.fixture
def sample_report():
    return AssessmentReport(
        domain="example.com",
        timestamp="2026-11-13T00:00:00Z",
        score=82,
        grade="B",
        spf=SPFResult(record="v=spf1 ~all", is_valid=True, all_mechanism="~all", lookup_count=0),
        dmarc=DMARCResult(record="v=DMARC1; p=reject", is_valid=True, policy="reject"),
        dkim=DKIMResult(),
        dnssec=DNSSECResult(is_enabled=False),
        nameservers=NameserverResult(nameservers=["ns1.example.com", "ns2.example.com"]),
        mx=MXResult(),
        all_findings=[
            Finding(
                title="SPF Softfail",
                severity=Severity.MEDIUM,
                description="Using ~all instead of -all",
                remediation="Upgrade to -all",
            ),
            Finding(
                title="DNSSEC Not Enabled",
                severity=Severity.MEDIUM,
                description="No DNSKEY found",
                remediation="Enable DNSSEC",
            ),
        ],
    )


def test_format_json(sample_report):
    json_str = format_json(sample_report)
    data = json.loads(json_str)
    assert data["domain"] == "example.com"
    assert data["score"] == 82
    assert data["grade"] == "B"
    assert len(data["all_findings"]) == 2


def test_format_markdown(sample_report):
    md_str = format_markdown(sample_report)
    assert "# DNS Health & Email Spoofing Assessment: example.com" in md_str
    assert "**Security Score:** **82 / 100**" in md_str
    assert "**Security Grade:** **B**" in md_str
    assert "SPF Softfail" in md_str
    assert "Upgrade to -all" in md_str


def test_cli_json_output(capsys):
    with patch("dns_recon.cli.run_full_assessment") as mock_run:
        mock_run.return_value = AssessmentReport(
            domain="example.com",
            timestamp="2026-11-13T00:00:00Z",
            score=100,
            grade="A+",
            spf=SPFResult(is_valid=True),
            dmarc=DMARCResult(is_valid=True),
            dkim=DKIMResult(),
            dnssec=DNSSECResult(),
            nameservers=NameserverResult(),
            mx=MXResult(),
        )
        exit_code = main(["example.com", "--json"])
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["domain"] == "example.com"
        assert data["score"] == 100


def test_cli_report_export(tmp_path):
    report_file = tmp_path / "scan_report.md"
    with patch("dns_recon.cli.run_full_assessment") as mock_run:
        mock_run.return_value = AssessmentReport(
            domain="example.com",
            timestamp="2026-11-13T00:00:00Z",
            score=90,
            grade="A",
            spf=SPFResult(is_valid=True),
            dmarc=DMARCResult(is_valid=True),
            dkim=DKIMResult(),
            dnssec=DNSSECResult(),
            nameservers=NameserverResult(),
            mx=MXResult(),
        )
        exit_code = main(["example.com", "-o", str(report_file)])
        assert exit_code == 0
        assert report_file.exists()
        content = report_file.read_text(encoding="utf-8")
        assert "DNS Health & Email Spoofing Assessment" in content


def test_cli_nxdomain_error(capsys):
    from dns_recon.dns_client import DNSLookupError
    with patch("dns_recon.cli.run_full_assessment", side_effect=DNSLookupError("Domain does not exist")):
        exit_code = main(["invalid-nonexistent-domain.xyz"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Domain does not exist" in captured.err or "Domain does not exist" in captured.out


def test_cli_osint_mode(capsys):
    from dns_recon.models import InfoGatherResult, IPRecord, SubdomainRecord
    mock_osint = InfoGatherResult(
        domain="example.com",
        timestamp="2026-11-16T12:00:00Z",
        ips=[IPRecord(ip="93.184.216.34", version="IPv4", provider="Edgecast")],
        nameservers=["ns1.example.com"],
        mx_records=["10 mail.example.com"],
        subdomains=[SubdomainRecord(subdomain="www.example.com", record_type="A", target="93.184.216.34", is_live=True)],
        detected_host="Edgecast",
    )
    with patch("dns_recon.cli.DNSClient.domain_exists", return_value=True):
        with patch("dns_recon.cli.gather_information", return_value=mock_osint):
            exit_code = main(["example.com", "--info", "--json"])
            assert exit_code == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["domain"] == "example.com"
            assert data["detected_host"] == "Edgecast"
            assert len(data["ips"]) == 1
