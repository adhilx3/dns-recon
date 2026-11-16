import io
import json
from unittest.mock import MagicMock, patch
import urllib.error
import pytest

from dns_recon.analyzers.osint import (
    detect_provider,
    fetch_crt_sh_subdomains,
    gather_information,
)
from dns_recon.dns_client import DNSClient


def test_detect_provider():
    assert detect_provider("104.21.5.12.cloudflare.com") == "Cloudflare CDN & Edge"
    assert detect_provider("ec2-1-2-3-4.compute-1.amazonaws.com") == "Amazon Web Services (AWS)"
    assert detect_provider("cname.vercel-dns.com") == "Vercel"
    assert detect_provider("random.server.local") is None


def test_fetch_crt_sh_subdomains_success():
    mock_payload = [
        {"name_value": "api.example.com\n*.staging.example.com"},
        {"name_value": "dev.example.com"},
        {"name_value": "unrelated.other.org"},
    ]
    mock_response = io.BytesIO(json.dumps(mock_payload).encode("utf-8"))
    mock_response.status = 200

    with patch("urllib.request.urlopen", return_value=mock_response):
        subs = fetch_crt_sh_subdomains("example.com")
        assert "api.example.com" in subs
        assert "staging.example.com" in subs
        assert "dev.example.com" in subs
        assert "unrelated.other.org" not in subs


def test_fetch_crt_sh_subdomains_error_handling():
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
        subs = fetch_crt_sh_subdomains("example.com")
        assert subs == set()


def test_gather_information():
    mock_client = MagicMock(spec=DNSClient)
    mock_client.resolve_cname.return_value = None
    mock_client.resolve_ips_for_name.side_effect = lambda h: ["104.21.5.12"] if h in ("example.com", "www.example.com") else []
    mock_client.resolve_aaaa.return_value = ["2606:4700:3038::6815:50c"]
    mock_client.resolve_ptr.side_effect = lambda ip: ["104-21-5-12.cloudflare.com"] if "104.21" in ip else []
    mock_client.query_records.side_effect = lambda d, r: ["ns1.cloudflare.com", "ns2.cloudflare.com"] if r == "NS" else ["10 mail.example.com"]

    with patch("dns_recon.analyzers.osint.fetch_crt_sh_subdomains", return_value={"api.example.com", "dev.example.com"}):
        result = gather_information(mock_client, "example.com", fetch_ct_logs=True, max_subdomain_probes=10)

        assert result.domain == "example.com"
        assert len(result.ips) == 2
        assert result.ips[0].ip == "104.21.5.12"
        assert result.ips[0].version == "IPv4"
        assert result.ips[0].provider == "Cloudflare CDN & Edge"
        assert result.detected_host == "Cloudflare CDN & Edge"
        assert len(result.nameservers) == 2
        assert len(result.mx_records) == 1
        assert len(result.subdomains) > 0
        assert any(s.subdomain == "www.example.com" and s.is_live for s in result.subdomains)
