from __future__ import annotations
import sys
from pathlib import Path
from starlette.types import ASGIApp, Scope, Receive, Send

# Add src directory to Python path so dns_recon package can be imported on Vercel
root_dir = Path(__file__).resolve().parent.parent
src_dir = root_dir / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from dns_recon.web import app as raw_app


class VercelPathMiddleware:
    """
    Middleware to handle Vercel rewrites and restore the original request path
    from the x-matched-path header.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            headers = dict(scope.get("headers", []))
            # Debug header check
            matched = headers.get(b"x-matched-path")
            forwarded_uri = headers.get(b"x-forwarded-uri")
            url_path = None
            if matched:
                url_path = matched.decode("utf-8").split("?")[0]
            elif forwarded_uri:
                url_path = forwarded_uri.decode("utf-8").split("?")[0]

            if url_path:
                scope["path"] = url_path
            elif scope["path"] in ("/api/index", "/api/index/"):
                scope["path"] = "/"
        await self.app(scope, receive, send)


app = VercelPathMiddleware(raw_app)
