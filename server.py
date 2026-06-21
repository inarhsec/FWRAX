"""
FWRAX web server entry point.

Usage:
  python server.py                    # default: 0.0.0.0:8000
  python server.py --host 127.0.0.1 --port 9000
  uvicorn server:app --reload         # development with auto-reload
"""
from __future__ import annotations

import argparse
import logging
import sys

from utils.helpers import setup_logging

setup_logging(logging.INFO)

from web.app import create_app  # noqa: E402

app = create_app()


def main() -> None:
    parser = argparse.ArgumentParser(description="FWRAX Web Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload (development)")
    parser.add_argument("--log-level", default="info", choices=("debug","info","warning","error"))
    args = parser.parse_args()

    try:
        import uvicorn
    except ImportError:
        print("uvicorn is required: pip install uvicorn", file=sys.stderr)
        sys.exit(1)

    print(f"🔥 FWRAX Web UI starting on http://{args.host}:{args.port}")
    uvicorn.run(
        "server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level=args.log_level,
    )


if __name__ == "__main__":
    main()
