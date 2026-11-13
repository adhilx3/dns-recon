from __future__ import annotations
import base64
from typing import TYPE_CHECKING

from dns_recon.models import DKIMResult, DKIMSelectorResult, Finding, Severity

if TYPE_CHECKING:
    from dns_recon.dns_client import DNSClient

DEFAULT_SELECTORS = [
    "default",
    "google",
    "k1",
    "mail",
    "selector1",
    "s1",
    "2023",
    "2024",
    "2025",
    "2026",
    "smtp",
    "mandrill",
    "sendgrid",
    "zoho",
]


def _parse_dkim_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def _estimate_key_size(public_key_b64: str) -> int:
    """Estimate RSA key size in bits from base64 public key string."""
    cleaned = public_key_b64.replace("\n", "").replace("\r", "").replace(" ", "")
    try:
        raw_bytes = base64.b64decode(cleaned)
        # In DER encoded SubjectPublicKeyInfo, raw_bytes length is approximately:
        # 512-bit RSA: ~94 bytes
        # 1024-bit RSA: ~162 bytes
        # 2048-bit RSA: ~294 bytes
        # 4096-bit RSA: ~550 bytes
        length = len(raw_bytes)
        if length <= 120:
            return 512
        elif length <= 220:
            return 1024
        elif length <= 400:
            return 2048
        else:
            return 4096
    except Exception:
        # Fallback approximation from base64 length
        if len(cleaned) < 200:
            return 512
        elif len(cleaned) < 350:
            return 1024
        elif len(cleaned) < 650:
            return 2048
        return 4096


def analyze_dkim(
    client: DNSClient,
    domain: str,
    selectors: list[str] | None = None,
) -> DKIMResult:
    """Probe DKIM selectors for the domain and evaluate key strengths."""
    to_test = selectors if selectors else DEFAULT_SELECTORS
    found_selectors: list[DKIMSelectorResult] = []
    findings: list[Finding] = []

    for selector in to_test:
        dkim_domain = f"{selector}._domainkey.{domain}"
        txt_records = client.resolve_txt_records(dkim_domain)
        for rec in txt_records:
            if "v=dkim1" in rec.lower() or "p=" in rec.lower():
                tags = _parse_dkim_tags(rec)
                pub_key = tags.get("p", "")
                k_type = tags.get("k", "rsa")
                key_size = _estimate_key_size(pub_key) if pub_key else None

                found_selectors.append(
                    DKIMSelectorResult(
                        selector=selector,
                        found=True,
                        record=rec,
                        key_size=key_size,
                        key_type=k_type,
                    )
                )

                if pub_key == "":
                    if not any("Revoked / Disabled DKIM" in f.title for f in findings):
                        findings.append(
                            Finding(
                                title="Revoked / Disabled DKIM Key (p=)",
                                severity=Severity.INFO,
                                description=f"DKIM record for selector '{selector}' publishes an empty public key (p=), explicitly disabling/revoking signing under RFC 6376 Section 6.1.2.",
                                remediation="Normal and compliant behavior for non-sending domains or decommissioned selectors.",
                            )
                        )
                elif key_size and key_size < 1024:
                    findings.append(
                        Finding(
                            title=f"Critical Weak DKIM Key Size ({key_size}-bit on {selector})",
                            severity=Severity.CRITICAL,
                            description=f"DKIM selector '{selector}' uses an insecure {key_size}-bit RSA key. Keys under 1024 bits can be factored and forged by attackers.",
                            remediation="Upgrade DKIM key to at least 2048-bit RSA.",
                        )
                    )
                elif key_size and key_size == 1024:
                    findings.append(
                        Finding(
                            title=f"Weak DKIM Key Size (1024-bit on {selector})",
                            severity=Severity.MEDIUM,
                            description=f"DKIM selector '{selector}' uses a 1024-bit RSA key. Industry standards and NIST recommend at least 2048-bit keys.",
                            remediation="Migrate to a 2048-bit RSA key for stronger cryptographic resilience.",
                        )
                    )
                elif key_size and key_size >= 2048:
                    findings.append(
                        Finding(
                            title=f"Strong DKIM Key ({key_size}-bit on {selector})",
                            severity=Severity.INFO,
                            description=f"DKIM selector '{selector}' uses a robust {key_size}-bit key.",
                            remediation="Continue periodic key rotation.",
                        )
                    )
                break

    if not found_selectors:
        findings.append(
            Finding(
                title="No DKIM Selectors Discovered",
                severity=Severity.INFO,
                description=f"None of the {len(to_test)} tested selectors were found at *._domainkey.{domain}. DKIM selectors are not publicly discoverable via standard queries without guessing or inspecting email headers.",
                remediation="If DKIM is configured, verify your specific selector with the --selectors flag (e.g. --selectors custom1,k2).",
            )
        )

    return DKIMResult(
        tested_selectors=to_test,
        found_selectors=found_selectors,
        findings=findings,
    )

