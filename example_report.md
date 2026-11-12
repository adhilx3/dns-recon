# DNS Health & Email Spoofing Assessment: google.com
**Generated:** 2026-11-12T20:13:08.549559+00:00 (UTC)  
**Security Score:** **81 / 100**  
**Security Grade:** **B**  

## Executive Summary
| Protocol / Area | Status | Key Highlights |
| :--- | :--- | :--- |
| **SPF** | ✅ Valid | `~all` (1 DNS lookups) |
| **DMARC** | ✅ Enforcing | Policy: `p=reject` (pct=100%) |
| **DKIM** | ℹ️ Unverified | No default selectors found |
| **DNSSEC** | ⚠️ Disabled | Zone is not cryptographically signed |
| **Nameservers & AXFR** | ✅ Secure | 4 nameserver(s); AXFR: Denied |
| **MX Records** | ✅ Active | 1 MX server(s) configured |

## Findings & Remediation Guidance
| Severity | Finding | Details & Impact | Recommended Remediation |
| :--- | :--- | :--- | :--- |
| **MEDIUM** | SPF Softfail (~all) | The SPF record uses softfail (~all). Unauthorized emails may still reach recipient inboxes (or spam folders) unless backed by an enforcing DMARC policy. | Once email senders are inventoried, transition from '~all' to '-all'. |
| **MEDIUM** | DNSSEC Not Enabled | Neither DNSKEY nor DS records exist for 'google.com'. DNS responses are not cryptographically signed, leaving visitors vulnerable to DNS spoofing and cache poisoning (MitM attacks). | Enable DNSSEC in your authoritative DNS provider and configure the DS record at your domain registrar. |
| **LOW** | No DKIM Selectors Discovered | None of the 14 tested selectors were found at *._domainkey.google.com. DKIM selectors are not publicly discoverable via standard queries without guessing or inspecting email headers. | If DKIM is configured, verify your specific selector with the --selectors flag (e.g. --selectors custom1,k2). |
| **INFO** | DMARC Policy 'reject': Strong Anti-Spoofing Protection | Domain strictly rejects unauthenticated emails, providing full anti-spoofing defense. | Maintain alignment between envelope sender and header From domain. |
| **INFO** | DNS Zone Transfers (AXFR) Denied | All tested authoritative nameservers properly refused unauthorized zone transfers. | Maintain existing access control lists (ACLs). |
| **INFO** | 1 MX Record(s) Configured | Found 1 mail exchange server(s): smtp.google.com.. | Ensure mail servers support opportunistic TLS (STARTTLS). |

## Published Records
```text
SPF:   v=spf1 include:_spf.google.com ~all
DMARC: v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com
MX:    pref=10 host=smtp.google.com.
NS:    ns4.google.com
NS:    ns3.google.com
NS:    ns2.google.com
NS:    ns1.google.com
```