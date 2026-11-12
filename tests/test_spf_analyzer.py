from unittest.mock import MagicMock
import pytest

from dns_recon.models import Severity
from dns_recon.analyzers.spf import analyze_spf


def test_missing_spf():
    mock_client = MagicMock()
    mock_client.resolve_txt_records.return_value = ["v=something_else"]
    
    result = analyze_spf(mock_client, "example.com")
    assert result.is_valid is False
    assert result.record is None
    assert any(f.severity == Severity.HIGH and "Missing SPF" in f.title for f in result.findings)


def test_multiple_spf_records():
    mock_client = MagicMock()
    mock_client.resolve_txt_records.return_value = [
        "v=spf1 include:_spf1.example.com -all",
        "v=spf1 include:_spf2.example.com -all",
    ]
    
    result = analyze_spf(mock_client, "example.com")
    assert result.is_valid is False
    assert any(f.severity == Severity.CRITICAL and "Multiple SPF" in f.title for f in result.findings)


def test_permissive_all_plus():
    mock_client = MagicMock()
    mock_client.resolve_txt_records.return_value = ["v=spf1 +all"]
    
    result = analyze_spf(mock_client, "example.com")
    assert result.is_valid is True
    assert result.all_mechanism == "+all"
    assert any(f.severity == Severity.CRITICAL and "+all" in f.title for f in result.findings)


def test_neutral_all_question():
    mock_client = MagicMock()
    mock_client.resolve_txt_records.return_value = ["v=spf1 ?all"]
    
    result = analyze_spf(mock_client, "example.com")
    assert result.is_valid is True
    assert result.all_mechanism == "?all"
    assert any(f.severity == Severity.HIGH and "?all" in f.title for f in result.findings)


def test_softfail_all_tilde():
    mock_client = MagicMock()
    mock_client.resolve_txt_records.return_value = ["v=spf1 include:_spf.google.com ~all"]
    # when queried for _spf.google.com
    def mock_resolve(domain):
        if domain == "example.com":
            return ["v=spf1 include:_spf.google.com ~all"]
        if domain == "_spf.google.com":
            return ["v=spf1 ip4:192.0.2.0/24 -all"]
        return []
    mock_client.resolve_txt_records.side_effect = mock_resolve

    result = analyze_spf(mock_client, "example.com")
    assert result.is_valid is True
    assert result.all_mechanism == "~all"
    assert any(f.severity == Severity.MEDIUM and "~all" in f.title for f in result.findings)
    assert result.lookup_count == 1  # 1 include lookup


def test_strict_hardfail_minus():
    mock_client = MagicMock()
    mock_client.resolve_txt_records.return_value = ["v=spf1 ip4:198.51.100.0/24 -all"]
    
    result = analyze_spf(mock_client, "example.com")
    assert result.is_valid is True
    assert result.all_mechanism == "-all"
    assert result.lookup_count == 0  # ip4 does not trigger DNS lookup


def test_excessive_lookups_exceeds_10():
    mock_client = MagicMock()
    # 11 includes
    includes = " ".join([f"include:spf{i}.example.com" for i in range(12)])
    record = f"v=spf1 {includes} -all"
    
    def mock_resolve(domain):
        if domain == "example.com":
            return [record]
        return ["v=spf1 ip4:192.0.2.1 -all"]
        
    mock_client.resolve_txt_records.side_effect = mock_resolve
    
    result = analyze_spf(mock_client, "example.com")
    assert result.lookup_count >= 12
    assert any(f.severity == Severity.HIGH and "Lookup Limit Exceeded" in f.title for f in result.findings)


def test_circular_include_protection():
    mock_client = MagicMock()
    def mock_resolve(domain):
        if domain == "example.com":
            return ["v=spf1 include:loop.example.com -all"]
        if domain == "loop.example.com":
            return ["v=spf1 include:example.com -all"]
        return []
    mock_client.resolve_txt_records.side_effect = mock_resolve
    
    result = analyze_spf(mock_client, "example.com")
    assert result.is_valid is True
    assert result.lookup_count == 2
