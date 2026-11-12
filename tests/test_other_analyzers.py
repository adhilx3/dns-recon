from unittest.mock import MagicMock, patch
import pytest

from dns_recon.models import RecordType, Severity
from dns_recon.analyzers.dkim import analyze_dkim
from dns_recon.analyzers.dnssec import analyze_dnssec
from dns_recon.analyzers.nameserver import analyze_nameservers
from dns_recon.analyzers.mx import analyze_mx


def test_dkim_selector_found_and_weak_key():
    mock_client = MagicMock()
    # 512-bit weak RSA key in base64 is ~88 chars
    mock_client.resolve_txt_records.return_value = ["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDd"]
    
    result = analyze_dkim(mock_client, "example.com", selectors=["default"])
    assert len(result.found_selectors) == 1
    assert result.found_selectors[0].selector == "default"
    assert any("Weak DKIM Key" in f.title for f in result.findings)


def test_dkim_no_selectors_found():
    mock_client = MagicMock()
    mock_client.resolve_txt_records.return_value = []
    
    result = analyze_dkim(mock_client, "example.com", selectors=["default", "google"])
    assert len(result.found_selectors) == 0
    assert any("No DKIM Selectors Discovered" in f.title for f in result.findings)


def test_dnssec_disabled():
    mock_client = MagicMock()
    mock_client.query_records.return_value = []
    
    result = analyze_dnssec(mock_client, "example.com")
    assert result.is_enabled is False
    assert any(f.severity == Severity.MEDIUM and "DNSSEC Not Enabled" in f.title for f in result.findings)


def test_dnssec_enabled():
    mock_client = MagicMock()
    def mock_query(domain, rtype):
        if rtype == RecordType.DNSKEY:
            return ["257 3 13 oJMIL..."]
        if rtype == RecordType.DS:
            return ["2371 13 2 1234abcd..."]
        return []
    mock_client.query_records.side_effect = mock_query
    
    result = analyze_dnssec(mock_client, "example.com")
    assert result.is_enabled is True
    assert result.dnskey_count == 1
    assert result.ds_count == 1
    assert any("DNSSEC Configured" in f.title for f in result.findings)


def test_nameserver_insufficient_redundancy():
    mock_client = MagicMock()
    mock_client.query_records.return_value = ["ns1.example.com."]
    mock_client.test_zone_transfer.return_value = (False, [])
    
    result = analyze_nameservers(mock_client, "example.com")
    assert len(result.nameservers) == 1
    assert any(f.severity == Severity.HIGH and "Insufficient Nameserver" in f.title for f in result.findings)


def test_nameserver_axfr_vulnerable():
    mock_client = MagicMock()
    mock_client.query_records.return_value = ["ns1.example.com.", "ns2.example.com."]
    mock_client.test_zone_transfer.side_effect = [
        (True, ["@", "admin", "secret", "vpn"]),
        (False, []),
    ]
    
    result = analyze_nameservers(mock_client, "example.com")
    assert any(f.severity == Severity.CRITICAL and "Open DNS Zone Transfer (AXFR)" in f.title for f in result.findings)


def test_mx_records():
    mock_client = MagicMock()
    mock_client.query_records.return_value = ["10 mail1.example.com.", "20 mail2.example.com."]
    
    result = analyze_mx(mock_client, "example.com")
    assert len(result.records) == 2
    assert result.records[0].exchange == "mail1.example.com."
    assert result.records[0].preference == 10
