from unittest.mock import MagicMock
import pytest

from dns_recon.models import Severity
from dns_recon.analyzers.dmarc import analyze_dmarc


def test_missing_dmarc():
    mock_client = MagicMock()
    mock_client.resolve_txt_records.return_value = []
    
    result = analyze_dmarc(mock_client, "example.com")
    assert result.is_valid is False
    assert result.record is None
    assert any(f.severity == Severity.CRITICAL and "Missing DMARC" in f.title for f in result.findings)


def test_dmarc_policy_none():
    mock_client = MagicMock()
    mock_client.resolve_txt_records.return_value = ["v=DMARC1; p=none; rua=mailto:dmarc@example.com"]
    
    result = analyze_dmarc(mock_client, "example.com")
    assert result.is_valid is True
    assert result.policy == "none"
    assert any(f.severity == Severity.HIGH and "Monitoring Only" in f.title for f in result.findings)


def test_dmarc_policy_quarantine():
    mock_client = MagicMock()
    mock_client.resolve_txt_records.return_value = ["v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@example.com"]
    
    result = analyze_dmarc(mock_client, "example.com")
    assert result.is_valid is True
    assert result.policy == "quarantine"
    assert any(f.severity == Severity.MEDIUM and "quarantine" in f.title for f in result.findings)


def test_dmarc_policy_reject():
    mock_client = MagicMock()
    mock_client.resolve_txt_records.return_value = ["v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com; ruf=mailto:dmarc@example.com"]
    
    result = analyze_dmarc(mock_client, "example.com")
    assert result.is_valid is True
    assert result.policy == "reject"
    assert result.pct == 100
    assert "mailto:dmarc@example.com" in result.rua
    assert any(f.severity == Severity.INFO and "reject" in f.title for f in result.findings)


def test_dmarc_partial_pct():
    mock_client = MagicMock()
    mock_client.resolve_txt_records.return_value = ["v=DMARC1; p=reject; pct=50; rua=mailto:dmarc@example.com"]
    
    result = analyze_dmarc(mock_client, "example.com")
    assert result.pct == 50
    assert any(f.severity == Severity.MEDIUM and "pct < 100" in f.title for f in result.findings)


def test_dmarc_missing_rua():
    mock_client = MagicMock()
    mock_client.resolve_txt_records.return_value = ["v=DMARC1; p=reject"]
    
    result = analyze_dmarc(mock_client, "example.com")
    assert any(f.severity == Severity.LOW and "Missing DMARC Aggregate Reporting" in f.title for f in result.findings)


def test_dmarc_multiple_records():
    mock_client = MagicMock()
    mock_client.resolve_txt_records.return_value = [
        "v=DMARC1; p=reject",
        "v=DMARC1; p=none",
    ]
    
    result = analyze_dmarc(mock_client, "example.com")
    assert result.is_valid is False
    assert any(f.severity == Severity.CRITICAL and "Multiple DMARC Records" in f.title for f in result.findings)


def test_dmarc_subdomain_policy_none():
    mock_client = MagicMock()
    mock_client.resolve_txt_records.return_value = ["v=DMARC1; p=reject; sp=none; rua=mailto:dmarc@example.com"]
    
    result = analyze_dmarc(mock_client, "example.com")
    assert result.subdomain_policy == "none"
    assert any(f.severity == Severity.HIGH and "sp=none" in f.title for f in result.findings)
