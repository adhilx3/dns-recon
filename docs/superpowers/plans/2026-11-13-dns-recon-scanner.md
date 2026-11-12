# DNS Health & Email Spoofing Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a robust, modular Python CLI reconnaissance scanner (`dns-recon`) that inspects domains for email spoofing defenses (SPF, DMARC, DKIM), DNS hygiene (DNSSEC, MX records, nameserver redundancy), and open zone transfer (AXFR) vulnerabilities, with rich terminal rendering and JSON/Markdown export.

**Architecture:** A layered architecture with a DNS client wrapper (`dnspython`), modular analyzers for each security domain (SPF, DMARC, DKIM, DNSSEC, Nameserver/AXFR), a centralized risk-scoring engine that aggregates findings into structured severity scores (0-100 / Grade A-F), and formatters for Rich terminal output, JSON, and Markdown reports.

**Tech Stack:** Python 3.10+, `dnspython`, `rich`, `pytest`.

**Spec:** `docs/spec.md`

## Global Constraints

- Python version floor: Python 3.10+
- Production runtime dependencies limited to: `dnspython>=2.6.0`, `rich>=13.0.0`
- Zero external network dependencies during tests: all DNS queries mocked via unit tests
- Error handling must gracefully handle `NXDOMAIN`, `NoAnswer`, `Timeout`, and network unreachable errors without unhandled exceptions
- Standard CLI invocation via `python -m dns_recon.cli <domain>` or `dns-recon <domain>`

## Review Focus

1. Domain does not exist (`NXDOMAIN`): graceful error message and non-zero exit code without stack traces.
2. Domain has multiple conflicting SPF records (RFC 7208 §3.2 violation): flag as CRITICAL and mark SPF as completely broken/invalid.
3. DMARC policy set to `p=none`: correctly warn that spoofing is permitted and degrade overall security score.
4. Nameserver refuses or drops AXFR queries: handle Refused, FormErr, or ConnectionReset cleanly as "Zone transfer not allowed (secure)".
5. Extremely long or recursive SPF `include:` loops: track lookup depth and guard against circular reference infinite loops.

---

### Task 1: Project Scaffolding, Models, and DNS Client Wrapper

**Files:**
- Create: `pyproject.toml`
- Create: `src/dns_recon/__init__.py`
- Create: `src/dns_recon/models.py`
- Create: `src/dns_recon/dns_client.py`
- Create: `tests/__init__.py`
- Create: `tests/test_dns_client.py`

**Interfaces:**
- Produces:
  - `Severity` enum: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
  - `Finding` dataclass: `title: str`, `severity: Severity`, `description: str`, `remediation: str`
  - `DNSClient`: `query_records(domain: str, record_type: str) -> list[str]`, `resolve_txt_records(domain: str) -> list[str]`, `test_zone_transfer(domain: str, nameserver: str) -> bool`

- [ ] **Step 1: Write the failing tests for DNSClient and Models**

```python
# tests/test_dns_client.py
from dns_recon.models import Finding, Severity
from dns_recon.dns_client import DNSClient

def test_models():
    f = Finding(title="Test", severity=Severity.HIGH, description="Desc", remediation="Fix")
    assert f.severity == Severity.HIGH

def test_query_records_mocked(mocker):
    # Mock dnspython resolver
    client = DNSClient()
    # Test returns list of string records
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_dns_client.py -v`
Expected: FAIL (modules not found)

- [ ] **Step 3: Implement project config, models, and DNSClient**

Create `pyproject.toml`, `models.py`, and `dns_client.py` with resolver fallback and exception handling.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_dns_client.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml src/ tests/
git commit -m "feat: setup project scaffolding, models, and dns_client"
```

---

### Task 2: SPF Analyzer (Syntax, Qualifiers, Lookup Limit, Multiple Records)

**Files:**
- Create: `src/dns_recon/analyzers/spf.py`
- Create: `tests/test_spf_analyzer.py`

**Interfaces:**
- Consumes: `DNSClient`, `Finding`, `Severity`
- Produces:
  - `SPFResult` dataclass: `record: str | None`, `is_valid: bool`, `all_mechanism: str | None`, `lookup_count: int`, `findings: list[Finding]`
  - `analyze_spf(client: DNSClient, domain: str) -> SPFResult`

- [ ] **Step 1: Write failing tests for SPF Analyzer**

Tests covering:
- No SPF record (HIGH finding)
- Multiple SPF records (CRITICAL finding)
- Permissive `+all` or `?all` (CRITICAL / HIGH finding)
- Softfail `~all` (MEDIUM finding)
- Strict `-all` (PASS / INFO finding)
- Excessive DNS lookups (> 10 lookups RFC 7208 violation)
- Recursive `include:` depth protection

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_spf_analyzer.py -v`
Expected: FAIL

- [ ] **Step 3: Implement `analyze_spf` in `src/dns_recon/analyzers/spf.py`**

Parse SPF records, extract mechanisms, recursively count includes (with visited set to prevent infinite loops), evaluate all-mechanism safety.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_spf_analyzer.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/dns_recon/analyzers/spf.py tests/test_spf_analyzer.py
git commit -m "feat: implement SPF analyzer with RFC 7208 validation"
```

---

### Task 3: DMARC Analyzer (Policy, Alignment, Reporting, Subdomains)

**Files:**
- Create: `src/dns_recon/analyzers/dmarc.py`
- Create: `tests/test_dmarc_analyzer.py`

**Interfaces:**
- Consumes: `DNSClient`, `Finding`, `Severity`
- Produces:
  - `DMARCResult` dataclass: `record: str | None`, `is_valid: bool`, `policy: str | None`, `subdomain_policy: str | None`, `pct: int`, `has_rua: bool`, `has_ruf: bool`, `findings: list[Finding]`
  - `analyze_dmarc(client: DNSClient, domain: str) -> DMARCResult`

- [ ] **Step 1: Write failing tests for DMARC Analyzer**

Tests covering:
- Missing DMARC record (CRITICAL finding)
- `p=none` monitoring-only policy (HIGH finding: allows spoofing)
- `p=quarantine` (MEDIUM finding: partial enforcement)
- `p=reject` (PASS: strong enforcement)
- `pct < 100` (MEDIUM finding: partial enforcement)
- Missing `rua` report destination (LOW finding)

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_dmarc_analyzer.py -v`
Expected: FAIL

- [ ] **Step 3: Implement `analyze_dmarc` in `src/dns_recon/analyzers/dmarc.py`**

Query `_dmarc.<domain>`, parse key-value tags (`p`, `sp`, `pct`, `rua`, `ruf`, `aspf`, `adkim`), generate findings and recommendations.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_dmarc_analyzer.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/dns_recon/analyzers/dmarc.py tests/test_dmarc_analyzer.py
git commit -m "feat: implement DMARC analyzer"
```

---

### Task 4: DKIM, MX, DNSSEC, and Nameserver/AXFR Analyzers

**Files:**
- Create: `src/dns_recon/analyzers/dkim.py`
- Create: `src/dns_recon/analyzers/dnssec.py`
- Create: `src/dns_recon/analyzers/nameserver.py`
- Create: `tests/test_other_analyzers.py`

**Interfaces:**
- Consumes: `DNSClient`, `Finding`, `Severity`
- Produces:
  - `analyze_dkim(client: DNSClient, domain: str, selectors: list[str]) -> DKIMResult`
  - `analyze_dnssec(client: DNSClient, domain: str) -> DNSSECResult`
  - `analyze_nameservers(client: DNSClient, domain: str) -> NameserverResult` (including AXFR check per nameserver)

- [ ] **Step 1: Write failing tests for DKIM, DNSSEC, and Nameserver analyzers**

Tests covering:
- DKIM selector discovery and RSA key length check
- DNSSEC presence (DNSKEY/DS) and absence (MEDIUM finding)
- Nameserver single-point-of-failure (< 2 NS records: HIGH finding)
- Zone transfer (AXFR): open transfer = CRITICAL finding, refused = secure

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_other_analyzers.py -v`
Expected: FAIL

- [ ] **Step 3: Implement DKIM, DNSSEC, and Nameserver analyzers**

Code implementation with proper parsing, selector iteration, and AXFR exception handling.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_other_analyzers.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/dns_recon/analyzers/ tests/test_other_analyzers.py
git commit -m "feat: implement DKIM, DNSSEC, and Nameserver/AXFR analyzers"
```

---

### Task 5: Scoring Engine & Complete Assessment Aggregator

**Files:**
- Create: `src/dns_recon/scoring.py`
- Create: `tests/test_scoring.py`

**Interfaces:**
- Consumes: `SPFResult`, `DMARCResult`, `DKIMResult`, `DNSSECResult`, `NameserverResult`
- Produces:
  - `AssessmentReport` dataclass containing all results, overall score (0-100), letter grade (A+, A, B, C, D, F), and flattened findings list.
  - `calculate_assessment(domain: str, ...results) -> AssessmentReport`

- [ ] **Step 1: Write failing test for scoring engine**

Test score calculations:
- Perfect domain with strict SPF `-all`, DMARC `p=reject`, DNSSEC, redundant NS -> 95-100 (Grade A/A+)
- Domain with no DMARC, permissive SPF `+all`, open AXFR -> < 40 (Grade F)
- Deductions aligned with severity weights (Critical: -25, High: -15, Medium: -8, Low: -3)

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_scoring.py -v`
Expected: FAIL

- [ ] **Step 3: Implement scoring engine in `src/dns_recon/scoring.py`**

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_scoring.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/dns_recon/scoring.py tests/test_scoring.py
git commit -m "feat: implement scoring engine and risk grader"
```

---

### Task 6: Formatters (Rich Console, JSON, Markdown Report) and CLI Entry Point

**Files:**
- Create: `src/dns_recon/formatters.py`
- Create: `src/dns_recon/cli.py`
- Create: `src/dns_recon/__main__.py`
- Create: `tests/test_cli.py`

**Interfaces:**
- Consumes: `AssessmentReport`
- Produces:
  - `format_console(report: AssessmentReport, console: Console)`
  - `format_json(report: AssessmentReport) -> str`
  - `format_markdown(report: AssessmentReport) -> str`
  - CLI argument parser accepting `domain`, `--json`, `--report <file>`, `--nameserver <ip>`, `--selectors <list>`

- [ ] **Step 1: Write failing tests for CLI and formatters**

Tests verifying JSON serialization, Markdown generation, and CLI exit codes (0 for clean scan, 1 for invalid domain/NXDOMAIN).

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_cli.py -v`
Expected: FAIL

- [ ] **Step 3: Implement formatters and CLI**

Build Rich tables, status badges, summary panels, and Markdown report builder.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_cli.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/dns_recon/formatters.py src/dns_recon/cli.py src/dns_recon/__main__.py tests/test_cli.py
git commit -m "feat: implement CLI interface and Rich/JSON/Markdown formatters"
```

---

### Task 7: End-to-End Verification & Documentation

**Files:**
- Create: `README.md`
- Create: `example_report.md` (generated from sample scan)

- [ ] **Step 1: Run full test suite with coverage**

Run: `python -m pytest tests/ -v`
Verify all tests pass with 0 failures.

- [ ] **Step 2: Verify live CLI against public test domain (e.g. google.com or cloudflare.com)**

Run: `python -m dns_recon.cli google.com`
Verify output tables, score, and badges display properly.

- [ ] **Step 3: Write comprehensive `README.md` with usage instructions, reconnaissance methodology, and sample output**

- [ ] **Step 4: Final commit**

```bash
git add README.md example_report.md
git commit -m "docs: add README and sample execution report"
```
