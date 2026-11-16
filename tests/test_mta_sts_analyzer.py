from unittest.mock import MagicMock
import pytest

from dns_recon.analyzers.mta_sts import analyze_mta_sts
from dns_recon.dns_client import DNSClient
from dns_recon.models import Severity


def test_mta_sts_both_missing():
    mock_client = MagicMock(spec=DNSClient)
    mock_client.resolve_txt_records.return_value = []

    res = analyze_mta_sts(mock_client, "example.com")
    assert not res.has_mta_sts
    assert not res.has_tls_rpt
    assert any("MTA-STS Not Configured" in f.title for f in res.findings)
    assert any("TLS-RPT) Not Configured" in f.title for f in res.findings)


def test_mta_sts_both_valid():
    mock_client = MagicMock(spec=DNSClient)

    def side_effect(host):
        if "_mta-sts" in host:
            return ["v=STSv1; id=20241101T010101;"]
        elif "_smtp._tls" in host:
            return ["v=TLSRPTv1; rua=mailto:tls-reports@example.com"]
        return []

    mock_client.resolve_txt_records.side_effect = side_effect

    res = analyze_mta_sts(mock_client, "example.com")
    assert res.has_mta_sts
    assert res.has_tls_rpt
    assert res.mta_sts_id == "20241101T010101"
    assert "mailto:tls-reports@example.com" in res.tls_rpt_rua
    assert any("MTA-STS & TLS-RPT Active" in f.title for f in res.findings)


def test_mta_sts_missing_id():
    mock_client = MagicMock(spec=DNSClient)

    def side_effect(host):
        if "_mta-sts" in host:
            return ["v=STSv1;"]
        elif "_smtp._tls" in host:
            return ["v=TLSRPTv1; rua=mailto:tls@example.com"]
        return []

    mock_client.resolve_txt_records.side_effect = side_effect

    res = analyze_mta_sts(mock_client, "example.com")
    assert not res.has_mta_sts
    assert any("Missing ID Tag" in f.title for f in res.findings)


def test_tls_rpt_missing_rua():
    mock_client = MagicMock(spec=DNSClient)

    def side_effect(host):
        if "_mta-sts" in host:
            return ["v=STSv1; id=1234;"]
        elif "_smtp._tls" in host:
            return ["v=TLSRPTv1;"]
        return []

    mock_client.resolve_txt_records.side_effect = side_effect

    res = analyze_mta_sts(mock_client, "example.com")
    assert res.has_mta_sts
    assert not res.has_tls_rpt
    assert any("Missing Reporting Destination" in f.title for f in res.findings)
