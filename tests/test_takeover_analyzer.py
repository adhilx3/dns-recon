from unittest.mock import MagicMock
import pytest

from dns_recon.analyzers.takeover import analyze_takeover, identify_service
from dns_recon.dns_client import DNSClient
from dns_recon.models import Severity


def test_identify_service():
    assert identify_service("myorg.github.io") == "GitHub Pages"
    assert identify_service("test.s3.amazonaws.com") == "AWS S3"
    assert identify_service("app.azurewebsites.net") == "Microsoft Azure Web App"
    assert identify_service("myshop.myshopify.com") == "Shopify"
    assert identify_service("unrelated.corp.internal") is None


def test_takeover_no_cnames():
    mock_client = MagicMock(spec=DNSClient)
    mock_client.resolve_cname.return_value = None

    res = analyze_takeover(mock_client, "example.com", subdomains=["dev", "blog"])
    assert res.dangling_count == 0
    assert len(res.cname_checks) == 0
    assert len(res.findings) == 0


def test_takeover_active_cname():
    mock_client = MagicMock(spec=DNSClient)

    def cname_resolver(host):
        if "dev.example.com" in host:
            return "cname.vercel-dns.com"
        return None

    mock_client.resolve_cname.side_effect = cname_resolver
    mock_client.host_exists.return_value = True

    res = analyze_takeover(mock_client, "example.com", subdomains=["dev"])
    assert res.dangling_count == 0
    assert len(res.cname_checks) == 1
    assert not res.cname_checks[0].is_dangling
    assert res.cname_checks[0].service == "Vercel"
    assert any("CNAME Records Verified Secure" in f.title for f in res.findings)


def test_takeover_dangling_critical():
    mock_client = MagicMock(spec=DNSClient)

    def cname_resolver(host):
        if "blog.example.com" in host:
            return "abandoned.github.io"
        return None

    mock_client.resolve_cname.side_effect = cname_resolver
    mock_client.host_exists.return_value = False  # NXDOMAIN

    res = analyze_takeover(mock_client, "example.com", subdomains=["blog"])
    assert res.dangling_count == 1
    assert res.cname_checks[0].is_dangling
    assert res.cname_checks[0].service == "GitHub Pages"
    assert any(f.severity == Severity.CRITICAL and "Potential Subdomain Takeover" in f.title for f in res.findings)


def test_takeover_dangling_generic_high():
    mock_client = MagicMock(spec=DNSClient)

    def cname_resolver(host):
        if "test.example.com" in host:
            return "nonexistent.oldcorp.com"
        return None

    mock_client.resolve_cname.side_effect = cname_resolver
    mock_client.host_exists.return_value = False

    res = analyze_takeover(mock_client, "example.com", subdomains=["test"])
    assert res.dangling_count == 1
    assert any(f.severity == Severity.HIGH and "Dangling CNAME Detected" in f.title for f in res.findings)
