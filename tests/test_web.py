from unittest.mock import MagicMock, patch
import pytest
from starlette.testclient import TestClient

from dns_recon.models import (
    AssessmentReport,
    DKIMResult,
    DNSSECResult,
    InfoGatherResult,
    IPRecord,
    MXResult,
    NameserverResult,
    SPFResult,
    DMARCResult,
    SubdomainRecord,
)
from dns_recon.dns_client import DNSLookupError
from dns_recon.web import app

client = TestClient(app)


def test_index_page():
    response = client.get("/")
    assert response.status_code == 200
    assert "DNS Recon & Email Spoofing Scanner" in response.text
    assert "Scan Domain" in response.text


def test_api_scan_success():
    mock_report = AssessmentReport(
        domain="example.com",
        timestamp="2026-11-13T00:00:00Z",
        score=95,
        grade="A+",
        spf=SPFResult(is_valid=True),
        dmarc=DMARCResult(is_valid=True, policy="reject"),
        dkim=DKIMResult(),
        dnssec=DNSSECResult(),
        nameservers=NameserverResult(),
        mx=MXResult(),
    )
    with patch("dns_recon.web.run_full_assessment", return_value=mock_report):
        response = client.get("/api/scan?domain=example.com")
        assert response.status_code == 200
        data = response.json()
        assert data["domain"] == "example.com"
        assert data["score"] == 95
        assert data["grade"] == "A+"


def test_api_scan_not_found():
    with patch("dns_recon.web.run_full_assessment", side_effect=DNSLookupError("Domain does not exist")):
        response = client.get("/api/scan?domain=invalid.xyz")
        assert response.status_code == 404
        assert "Domain does not exist" in response.json()["detail"]


def test_api_report_download():
    mock_report = AssessmentReport(
        domain="example.com",
        timestamp="2026-11-13T00:00:00Z",
        score=90,
        grade="A",
        spf=SPFResult(is_valid=True),
        dmarc=DMARCResult(is_valid=True, policy="reject"),
        dkim=DKIMResult(),
        dnssec=DNSSECResult(),
        nameservers=NameserverResult(),
        mx=MXResult(),
    )
    with patch("dns_recon.web.run_full_assessment", return_value=mock_report):
        response = client.get("/api/report?domain=example.com")
        assert response.status_code == 200
        assert "attachment; filename=\"example.com_dns_security_report.md\"" in response.headers["content-disposition"]
        assert "# DNS Health & Email Spoofing Assessment" in response.text


def test_api_info_gather_success():
    mock_osint = InfoGatherResult(
        domain="example.com",
        timestamp="2026-11-16T12:00:00Z",
        ips=[IPRecord(ip="93.184.216.34", version="IPv4", provider="Edgecast")],
        nameservers=["ns1.example.com"],
        mx_records=["10 mail.example.com"],
        subdomains=[SubdomainRecord(subdomain="www.example.com", record_type="A", target="93.184.216.34", is_live=True)],
        detected_host="Edgecast",
    )
    with patch("dns_recon.web.DNSClient.domain_exists", return_value=True):
        with patch("dns_recon.web.gather_information", return_value=mock_osint):
            response = client.get("/api/info-gather?domain=example.com")
            assert response.status_code == 200
            data = response.json()
            assert data["domain"] == "example.com"
            assert data["detected_host"] == "Edgecast"
            assert len(data["ips"]) == 1
            assert len(data["subdomains"]) == 1


def test_api_report_download_osint():
    mock_osint = InfoGatherResult(
        domain="example.com",
        timestamp="2026-11-16T12:00:00Z",
        ips=[IPRecord(ip="93.184.216.34", version="IPv4")],
        detected_host="Edgecast",
    )
    with patch("dns_recon.web.gather_information", return_value=mock_osint):
        response = client.get("/api/report?domain=example.com&type=osint")
        assert response.status_code == 200
        assert "example.com_osint_recon_report.md" in response.headers["content-disposition"]
        assert "# Information Gathering & OSINT Report" in response.text

