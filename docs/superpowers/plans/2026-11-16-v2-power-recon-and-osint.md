# DNS Recon v2 Implementation Plan: Power Recon & Information Gathering

## Overview
Expand DNS Recon to v2 with:
1. **Power Recon Analyzers**:
   - **BIMI** (`src/dns_recon/analyzers/bimi.py`): Query `default._bimi.<domain>`, validate `v=BIMI1`, SVG `l=`, VMC certificate `a=`.
   - **MTA-STS & TLS-RPT** (`src/dns_recon/analyzers/mta_sts.py`): Query `_mta-sts.<domain>` and `_smtp._tls.<domain>`, validate policies and reporting URIs.
   - **Subdomain Takeover & Dangling CNAMEs** (`src/dns_recon/analyzers/takeover.py`): Check CNAME records for target and common subdomains against cloud provider signatures (AWS, Azure, GitHub Pages, Heroku, Zendesk, etc.) and detect orphaned/dangling targets (NXDOMAIN).
2. **Information Gathering / OSINT Module** (`src/dns_recon/analyzers/osint.py`):
   - IP resolution (A IPv4, AAAA IPv6).
   - Reverse PTR lookups.
   - CDN / Cloud Host detection (Cloudflare, AWS, Vercel, Google Cloud, Fastly, Azure, etc.).
   - Subdomain enumeration via Certificate Transparency (`crt.sh`) + DNS wordlist permutation with active live status resolution.
3. **Data Models & Scoring**:
   - Update `models.py` with `BIMIResult`, `MTASTSResult`, `TakeoverResult`, `InfoGatherResult`, `SubdomainRecord`, `IPRecord`.
   - Update `scoring.py` with takeover penalties (-25 for CRITICAL dangling CNAME) and MTA-STS/BIMI hygiene findings.
4. **API Endpoints**:
   - Update `api/index.py` & `src/dns_recon/web.py`:
     - `/api/scan`: now includes BIMI, MTA-STS, and Takeover results.
     - `/api/info-gather`: performs OSINT, IP resolution, PTR, CDN detection, and subdomain enumeration.
5. **Web Dashboard (Vercel & Local)**:
   - Add responsive two-tab interface in `public/index.html` & `src/dns_recon/web.py`:
     - **Tab 1: 🛡️ Security & Spoofing Audit**: Score gauge, SPF, DMARC, DKIM, DNSSEC, Nameserver AXFR, MX, BIMI, MTA-STS, and Subdomain Takeover cards.
     - **Tab 2: 🌐 Information Gathering (OSINT)**: IP & PTR cards, CDN detection, interactive Subdomain Enumeration table with live search and CSV/JSON export.
6. **CLI & Formatters**:
   - Add `--info` / `--osint` CLI flags.
   - Format rich tables for BIMI, MTA-STS, Takeovers, and OSINT.
7. **Testing & Verification**:
   - Unit tests for all new analyzers with mocked DNS & HTTP.
   - Verify `pytest tests/` passes 100%.
   - Push to GitHub and verify live Vercel deployment.
