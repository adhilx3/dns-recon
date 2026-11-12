# DNS Health & Email Spoofing Scanner - Specification

## 1. Overview
`dns-recon` is a defensive reconnaissance and security auditing tool designed to evaluate the DNS hygiene and email spoofing resilience of target domain names. It assesses SPF, DMARC, DKIM, MX, DNSSEC, and Nameserver configurations (including zone transfer / AXFR vulnerabilities), generating a risk score and actionable remediation advice.

## 2. Target Users & Use Cases
- **Security Engineers & Blue Teams:** Auditing company and subsidiary domain assets against email spoofing (business email compromise / BEC prevention).
- **Penetration Testers & Bug Bounty Hunters:** Discovering misconfigured email authentication records, dangling CNAMEs, and unauthorized zone transfers during passive and active recon phases.
- **DevOps / Sysadmins:** Verifying new domain setups, SPF record limits, and DMARC enforcement.

## 3. Architecture & Components
1. **`dns_recon.dns_client`**: Low-level resolver interface wrapping `dnspython`, handling timeouts, custom nameservers, and fallback resolvers with clean error handling (`NXDOMAIN`, `NoAnswer`, `Timeout`).
2. **`dns_recon.analyzers.spf`**: SPF syntax validator, multiple-record detector, lookup-count calculator (10 lookup limit under RFC 7208), qualifier safety analysis (`+all`, `?all`, `~all`, `-all`), and redirect/include recursion.
3. **`dns_recon.analyzers.dmarc`**: DMARC record inspector (`_dmarc.<domain>`), policy strength evaluation (`none` vs `quarantine` vs `reject`), alignment flags, subdomain policy (`sp=`), and reporting destination verification (`rua`, `ruf`).
4. **`dns_recon.analyzers.dkim`**: Common and user-defined DKIM selector probe, public key extraction, key length/algorithm check, and weak key deprecation warnings.
5. **`dns_recon.analyzers.dnssec`**: DNSKEY and DS validation checking if DNSSEC is properly enabled and configured.
6. **`dns_recon.analyzers.nameserver`**: Nameserver redundancy audit, root/TLD sanity, and safe non-destructive AXFR (zone transfer) checks against each authoritative nameserver.
7. **`dns_recon.scoring`**: Quantitative scoring model (0-100 scale, letter grade A-F) deducting penalty points for missing or weak configurations (e.g. DMARC none = high risk, open AXFR = critical).
8. **`dns_recon.formatters`**: Output engines:
   - Rich terminal interface with color-coded badges, tables, and risk summaries.
   - Machine-readable JSON output (`--json`).
   - Markdown report export (`--report <path>`).
9. **`dns_recon.cli`**: CLI entry point with arguments for target domain, custom selectors, nameserver override, and output options.

## 4. Requirements & Constraints
- Python >= 3.10 compatible.
- Primary dependencies: `dnspython>=2.6.0`, `rich>=13.0.0`.
- Standalone runnable via `python -m dns_recon` or installed CLI entry point `dns-recon`.
- Test suite with 100% mocked DNS responses for fast, deterministic, network-independent test runs.

