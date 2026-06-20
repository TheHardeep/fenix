#!/usr/bin/env python3
"""Tiny static server for the Fenix developer docs.

The docs load Markdown with fetch(), which browsers block on file://, so the
site must be served over http://. Run this from the DocsSite folder:

    python serve.py            # serves on http://localhost:8080
    python serve.py 9000       # serves on a custom port

Then open the printed URL in your browser.
"""
from __future__ import annotations

import sys
import webbrowser
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    handler = partial(SimpleHTTPRequestHandler, directory=str(ROOT))
    url = f"http://localhost:{port}"
    with ThreadingHTTPServer(("127.0.0.1", port), handler) as httpd:
        print(f"Fenix Dev Docs  ->  {url}")
        print("Press Ctrl+C to stop.")
        try:
            webbrowser.open(url)
        except Exception:
            pass
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nStopped.")


if __name__ == "__main__":
    main()
