# dns-recon 🛡️
> **DNS Health, Security Hygiene & Email Spoofing Reconnaissance Scanner**

[![Live Demo](https://img.shields.io/badge/demo-dns--recon.vercel.app-blue?style=flat&logo=vercel)](https://dns-recon.vercel.app)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-45%20passing-brightgreen.svg)](tests/)

🌐 **Live Web Application:** [https://dns-recon.vercel.app](https://dns-recon.vercel.app)

`dns-recon` is a defensive reconnaissance and security auditing tool designed to audit any target domain for email spoofing susceptibility (SPF, DMARC, DKIM) and critical DNS hygiene issues (DNSSEC, nameserver redundancy, open AXFR zone transfers, MX configurations).

---

## ✨ Features

- **📧 Email Spoofing Defense Auditing:**
  - **SPF (RFC 7208):** Validates syntax, detects conflicting duplicate records (PermError), traces recursive `include:` statements, verifies the 10-lookup limit, and evaluates fallback mechanisms (`-all`, `~all`, `?all`, `+all`).
  - **DMARC (RFC 7489):** Inspects policy enforcement (`p=reject` vs `quarantine` vs `none`), subdomain policy inheritance (`sp=`), partial enforcement percentages (`pct < 100`), and aggregate reporting (`rua`).
  - **DKIM Discovery & Cryptographic Inspection:** Probes common and custom DKIM selectors, extracts public keys, and flags cryptographically obsolete or weak RSA key sizes (<2048-bit).
- **🌐 Infrastructure & DNS Hygiene:**
  - **DNSSEC Validation:** Queries DNSKEY and DS records to ensure end-to-end cryptographic trust chain validity.
  - **Zone Transfer (AXFR) Audit:** Non-destructively tests authoritative nameservers to identify open zone transfer vulnerabilities.
  - **Nameserver Redundancy (RFC 2182):** Verifies multiple authoritative nameservers to eliminate Single Points of Failure (SPOF).
  - **MX Configuration:** Analyzes mail server priority and routing records.
- **📊 Scoring & Reporting:**
  - **Security Score & Grade:** Quantitative 0–100 score and letter grade (A+ through F) weighted by vulnerability severity.
  - **Rich Terminal Interface:** Interactive colored tables, severity badges, and status panels.
  - **Multi-Format Export:** Machine-readable JSON output (`--json`) for automated pipelines, and Markdown executive summary reports (`-o report.md`).

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

### 4. Machine-Readable JSON Output
Integrate directly with CI/CD or security pipelines:

```bash
dns-recon example.com --json | jq .
```

### 5. Custom Nameserver & Specific DKIM Selectors
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

