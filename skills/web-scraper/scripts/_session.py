"""HTTP session construction and Mozilla cookies.txt persistence."""

from __future__ import annotations

import os
import sys

import requests


def _session(cookies_file: str | None = None) -> requests.Session:
    """Build a requests Session, optionally loading cookies from a Mozilla cookies.txt file."""
    s = requests.Session()
    if cookies_file and os.path.isfile(cookies_file):
        try:
            from http.cookiejar import MozillaCookieJar

            jar = MozillaCookieJar(cookies_file)
            jar.load(ignore_discard=True, ignore_expires=True)
            s.cookies = jar
        except Exception as e:
            print(f"⚠️ Failed to load cookies from {cookies_file}: {e}", file=sys.stderr)
    return s


def _save_cookies(session: requests.Session, cookies_file: str) -> None:
    """Persist session cookies to Mozilla cookies.txt format."""
    try:
        from http.cookiejar import MozillaCookieJar

        jar = MozillaCookieJar(cookies_file)
        for c in session.cookies:
            jar.set_cookie(c)
        jar.save(ignore_discard=True, ignore_expires=True)
    except Exception as e:
        print(f"⚠️ Failed to save cookies: {e}", file=sys.stderr)
