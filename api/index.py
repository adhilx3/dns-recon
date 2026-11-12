from __future__ import annotations
import sys
from pathlib import Path

# Add src directory to Python path so dns_recon package can be imported on Vercel
root_dir = Path(__file__).resolve().parent.parent
src_dir = root_dir / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from dns_recon.web import app
