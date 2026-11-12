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

from dns_recon.dns_client import DNSClient, DNSLookupError
from dns_recon.formatters import format_markdown
from dns_recon.scoring import run_full_assessment

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


@app.get("/api/report")
def api_report(domain: str = Query(...)) -> Response:
    client = DNSClient()
    try:
        report = run_full_assessment(domain=domain, client=client)
        md_content = format_markdown(report)
        return Response(
            content=md_content,
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="{domain}_dns_security_report.md"'},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
