from unittest.mock import MagicMock
import pytest

from dns_recon.analyzers.bimi import analyze_bimi, parse_bimi_tags
from dns_recon.dns_client import DNSClient
from dns_recon.models import Severity


def test_parse_bimi_tags():
    tags = parse_bimi_tags("v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem")
    assert tags["v"] == "BIMI1"
    assert tags["l"] == "https://example.com/logo.svg"
    assert tags["a"] == "https://example.com/cert.pem"


def test_bimi_not_published():
    mock_client = MagicMock(spec=DNSClient)
    mock_client.resolve_txt_records.return_value = []

    res = analyze_bimi(mock_client, "example.com")
    assert not res.is_valid
    assert res.record is None
    assert any(f.severity == Severity.INFO and "Not Published" in f.title for f in res.findings)


def test_bimi_valid_with_vmc():
    mock_client = MagicMock(spec=DNSClient)
    mock_client.resolve_txt_records.return_value = [
        "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"
    ]

    res = analyze_bimi(mock_client, "example.com")
    assert res.is_valid
    assert res.version == "BIMI1"
    assert res.location == "https://example.com/logo.svg"
    assert res.authority == "https://example.com/vmc.pem"
    assert any("BIMI Record Published" in f.title for f in res.findings)


def test_bimi_missing_location():
    mock_client = MagicMock(spec=DNSClient)
    mock_client.resolve_txt_records.return_value = ["v=BIMI1; a=https://example.com/vmc.pem"]

    res = analyze_bimi(mock_client, "example.com")
    assert not res.is_valid
    assert any(f.severity == Severity.MEDIUM and "URL Missing" in f.title for f in res.findings)


def test_bimi_insecure_location():
    mock_client = MagicMock(spec=DNSClient)
    mock_client.resolve_txt_records.return_value = [
        "v=BIMI1; l=http://example.com/logo.svg; a=https://example.com/vmc.pem"
    ]

    res = analyze_bimi(mock_client, "example.com")
    assert not res.is_valid
    assert any(f.severity == Severity.MEDIUM and "Insecure" in f.title for f in res.findings)


def test_bimi_no_vmc_info():
    mock_client = MagicMock(spec=DNSClient)
    mock_client.resolve_txt_records.return_value = ["v=BIMI1; l=https://example.com/logo.svg;"]

    res = analyze_bimi(mock_client, "example.com")
    assert res.is_valid
    assert any(f.severity == Severity.INFO and "VMC Certificate Not Configured" in f.title for f in res.findings)
