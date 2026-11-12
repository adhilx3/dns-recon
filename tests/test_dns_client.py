from unittest.mock import MagicMock, patch
import pytest
import dns.resolver
import dns.zone
import dns.query
import dns.exception

from dns_recon.models import Finding, Severity, RecordType
from dns_recon.dns_client import DNSClient, DNSLookupError


def test_models():
    finding = Finding(
        title="Test Finding",
        severity=Severity.HIGH,
        description="A test description.",
        remediation="Apply test fix."
    )
    assert finding.severity == Severity.HIGH
    assert finding.title == "Test Finding"
    assert finding.to_dict()["severity"] == "HIGH"


def test_dns_client_init():
    client = DNSClient(nameservers=["1.1.1.1"], timeout=3.0)
    assert client.nameservers == ["1.1.1.1"]
    assert client.timeout == 3.0


def test_query_records_success(mocker):
    client = DNSClient()
    mock_answer = [MagicMock(to_text=lambda: '"v=spf1 -all"')]
    
    with patch.object(client.resolver, "resolve", return_value=mock_answer):
        results = client.query_records("example.com", RecordType.TXT)
        assert results == ['"v=spf1 -all"']


def test_query_records_clean_quotes():
    client = DNSClient()
    mock_rr = MagicMock()
    mock_rr.to_text.return_value = '"v=spf1 include:_spf.example.com -all"'
    
    with patch.object(client.resolver, "resolve", return_value=[mock_rr]):
        results = client.resolve_txt_records("example.com")
        assert results == ["v=spf1 include:_spf.example.com -all"]


def test_query_records_nxdomain():
    client = DNSClient()
    with patch.object(client.resolver, "resolve", side_effect=dns.resolver.NXDOMAIN):
        with pytest.raises(DNSLookupError) as exc_info:
            client.query_records("nonexistent-domain-12345.xyz", RecordType.A)
        assert "does not exist" in str(exc_info.value)


def test_query_records_no_answer():
    client = DNSClient()
    with patch.object(client.resolver, "resolve", side_effect=dns.resolver.NoAnswer):
        results = client.query_records("example.com", RecordType.TXT)
        assert results == []


def test_zone_transfer_denied():
    client = DNSClient()
    with patch.object(client, "resolve_ips_for_name", return_value=["192.0.2.1"]):
        with patch("dns.zone.from_xfr", side_effect=dns.exception.FormError):
            success, records = client.test_zone_transfer("example.com", "ns1.example.com")
            assert success is False
            assert records == []


def test_zone_transfer_allowed():
    client = DNSClient()
    mock_zone = MagicMock()
    mock_zone.nodes.keys.return_value = ["@", "www", "mail"]
    with patch.object(client, "resolve_ips_for_name", return_value=["192.0.2.1"]):
        with patch("dns.zone.from_xfr", return_value=mock_zone):
            success, records = client.test_zone_transfer("example.com", "ns1.example.com")
            assert success is True
            assert "@" in records
