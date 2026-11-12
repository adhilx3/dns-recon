from unittest.mock import MagicMock, patch
import pytest
from starlette.testclient import TestClient

from dns_recon.models import (
    AssessmentReport,
    DKIMResult,
    DNSSECResult,
    MXResult,
    NameserverResult,
    SPFResult,
    DMARCResult,
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

