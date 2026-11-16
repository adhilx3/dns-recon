from __future__ import annotations
import sys
from pathlib import Path
from typing import Any
from fastapi import FastAPI, HTTPException, Query, Response

# Add src to sys.path
root_dir = Path(__file__).resolve().parent.parent
src_dir = root_dir / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from dns_recon.analyzers.osint import gather_information
from dns_recon.dns_client import DNSClient, DNSLookupError
from dns_recon.formatters import format_markdown, format_osint_markdown
from dns_recon.scoring import normalize_domain, run_full_assessment

app = FastAPI(title="DNS Recon API")


@app.get("/api/scan")
def api_scan(
    domain: str = Query(..., description="Target domain to scan"),
    selectors: str | None = Query(None, description="Comma-separated DKIM selectors"),
) -> dict[str, Any]:
    selector_list = [s.strip() for s in selectors.split(",") if s.strip()] if selectors else None
    client = DNSClient()

    try:
        report = run_full_assessment(domain=domain, client=client, selectors=selector_list)
        return report.to_dict()
    except DNSLookupError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan error: {e}")


@app.get("/api/info-gather")
@app.get("/api/osint")
def api_info_gather(
    domain: str = Query(..., description="Target domain to gather info on"),
) -> dict[str, Any]:
    client = DNSClient()
    clean_domain = normalize_domain(domain)

    if not clean_domain or not client.domain_exists(clean_domain):
        raise HTTPException(status_code=404, detail=f"Target domain '{clean_domain}' does not exist (NXDOMAIN).")

    try:
        osint_res = gather_information(client, clean_domain)
        return osint_res.to_dict()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OSINT error: {e}")


@app.get("/api/report")
def api_report(
    domain: str = Query(...),
    type: str = Query("security", description="Report type: 'security' or 'osint'"),
) -> Response:
    client = DNSClient()
    clean_domain = normalize_domain(domain)
    try:
        if type == "osint":
            osint_res = gather_information(client, clean_domain)
            md_content = format_osint_markdown(osint_res)
            filename = f"{clean_domain}_osint_recon_report.md"
        else:
            report = run_full_assessment(domain=clean_domain, client=client)
            md_content = format_markdown(report)
            filename = f"{clean_domain}_dns_security_report.md"

        return Response(
            content=md_content,
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
