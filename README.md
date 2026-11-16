# dns-recon 🛡️
> **DNS Health, Security Hygiene & Email Spoofing Reconnaissance Scanner (v2.0 Power Recon & OSINT)**

[![Live Demo](https://img.shields.io/badge/demo-dns--recon.vercel.app-blue?style=flat&logo=vercel)](https://dns-recon.vercel.app)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-70%20passing-brightgreen.svg)](tests/)

🌐 **Live Web Application:** [https://dns-recon.vercel.app](https://dns-recon.vercel.app)

`dns-recon` is a defensive reconnaissance and security auditing tool designed to audit any target domain for email spoofing susceptibility (SPF, DMARC, DKIM, BIMI, MTA-STS), dangling CNAME / subdomain takeover vulnerabilities, and deep OSINT information gathering (IPv4/IPv6 resolution, reverse PTR, cloud hosting detection, and Certificate Transparency subdomain discovery).

---

## ✨ Features (v2 Power Recon)

- **📧 Email Spoofing & Delivery Security:**
  - **SPF (RFC 7208):** Validates syntax, detects conflicting duplicate records (PermError), traces recursive `include:` statements, verifies the 10-lookup limit, and evaluates fallback mechanisms (`-all`, `~all`, `?all`, `+all`).
  - **DMARC (RFC 7489):** Inspects policy enforcement (`p=reject` vs `quarantine` vs `none`), subdomain policy inheritance (`sp=`), partial enforcement percentages (`pct < 100`), and aggregate reporting (`rua`).
  - **DKIM Discovery & Cryptographic Inspection:** Probes common and custom DKIM selectors, extracts public keys, and flags cryptographically obsolete or weak RSA key sizes (<2048-bit).
  - **BIMI (RFC Brand Indicators):** Verifies `default._bimi.<domain>` records, validates HTTPS SVG Tiny PS logo indicator links, and checks for Verified Mark Certificates (VMC).
  - **MTA-STS & TLS-RPT (RFC 8461 & 8460):** Audits strict transport security against STARTTLS stripping attacks and validates SMTP TLS reporting destinations.
- **🚨 Subdomain Takeover & Dangling CNAMEs:**
  - **15+ Cloud Provider Fingerprints:** Scans CNAME targets against known SaaS/cloud providers (AWS S3, CloudFront, GitHub Pages, Heroku, Azure, Shopify, Zendesk, Fastly, etc.).
  - **Dangling Target Detection:** Detects orphaned CNAME records pointing to NXDOMAIN / unallocated targets, flagging `CRITICAL` hijacking risks.
- **🌐 Information Gathering & OSINT Suite (New Tab):**
  - **IP Resolution & Reverse DNS:** Resolves IPv4 (A) and IPv6 (AAAA) records and automatically queries reverse PTR hostnames.
  - **Cloud / CDN Fingerprinting:** Identifies provider infrastructure (Cloudflare, AWS, Vercel, Google Cloud, Azure, Fastly, etc.).
  - **Subdomain Discovery & Live Status:** Queries public Certificate Transparency logs (`crt.sh`) combined with DNS dictionary probing, resolving live IP targets and flagging active vs inactive subdomains with real-time search filtering.
  - **Exporting:** One-click CSV and JSON export for discovered subdomains and target infrastructure.
- **📊 Scoring & Reporting:**
  - **Quantitative 0–100 Score & Letter Grade:** Weighted deductions based on vulnerability severity.
  - **Modern Dark-Mode Web Dashboard:** Interactive two-tab interface with live SVG score gauge.
  - **Rich Terminal CLI:** Color-coded tables and multi-format exports (Markdown & JSON).

---

## 🚀 Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/your-username/dns-recon.git
cd dns-recon

# Install package in editable mode
pip install -e .

# Or install with development/testing dependencies
pip install -e ".[dev]"
```

---

## 🛠️ Usage

### 1. Interactive Web Dashboard & GUI (Recommended)
Launch the modern browser dashboard with live visual score gauges and one-click report downloads:

```bash
dns-recon-web
# or
.\run_web.ps1
# or
run_web.bat
```
*Automatically opens `http://127.0.0.1:8000` in your default browser.*

---

### 2. Terminal CLI Scan
Audit any domain with rich terminal rendering:

```bash
dns-recon example.com
```

### 3. Export Detailed Markdown Report
Generate a Markdown security audit report with remediation steps:

```bash
dns-recon example.com -o audit_report.md
```

### 4. Reconnaissance & OSINT Information Gathering
Perform IP resolution, reverse PTR queries, and Certificate Transparency subdomain discovery:

```bash
dns-recon example.com --info
```

### 5. Full Comprehensive Audit (Security + OSINT)
Run both security audit and information gathering in a single run:

```bash
dns-recon example.com --all
```

### 6. Machine-Readable JSON Output
Integrate directly with CI/CD or security pipelines:

```bash
dns-recon example.com --json | jq .
```

### 7. Custom Nameserver & Specific DKIM Selectors
Query a specific DNS resolver and probe custom DKIM selectors:

```bash
dns-recon example.com -n 1.1.1.1 -s k1,mail,google,custom_selector
```

---

## 📈 Security Scoring Rubric

Scores start at **100 points** with deductions applied according to finding severity:

| Severity | Deduction | Example Findings |
| :--- | :---: | :--- |
| **CRITICAL** | **-25** | Open DNS Zone Transfer (AXFR), Missing DMARC record, Multiple SPF records, Permissive `+all` |
| **HIGH** | **-15** | DMARC `p=none` (Monitoring Only), SPF Lookup limit exceeded (>10), Single Nameserver SPOF |
| **MEDIUM** | **-8** | SPF Softfail (`~all`), DMARC `pct < 100`, Weak DKIM key (1024-bit), DNSSEC disabled |
| **LOW** | **-3** | Missing DMARC aggregate reporting (`rua`), No MX records |
| **INFO** | **0** | Strict SPF (`-all`), DMARC `reject`, DNSSEC active, AXFR denied |

### Grading Scale:
- **95 – 100:** `A+` (Exceptional defense, strictly enforced)
- **85 – 94:** `A` (Strong posture, minor improvements recommended)
- **75 – 84:** `B` (Good baseline, moderate exposure)
- **60 – 74:** `C` (Spoofing risk present, non-enforcing policies)
- **45 – 59:** `D` (High risk, missing critical defenses)
- **0 – 44:** `F` (Critical failure, easily spoofed by attackers)

---

## 🧪 Running Tests

The test suite runs with 100% mocked DNS calls, ensuring rapid, network-independent execution:

```bash
pytest tests/ -v
```

---

## 🛡️ License

This project is licensed under the MIT License.

