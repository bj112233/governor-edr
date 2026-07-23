"""Tests for CERT-IL RSS feed fetcher + IOC extraction + Markdown rendering.

Mocks the HTTP response to avoid network dependency in tests.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

_SCRIPTS = str(Path(__file__).resolve().parents[1] / "skills" / "intel-skill" / "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)


# Sample RSS XML mimicking the CERT-IL feed structure
_SAMPLE_RSS = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>CERT-IL Advisories</title>
    <item>
      <title>אזהרה: פגיעות קריטית CVE-2024-1234 בשרתי Apache</title>
      <description>התגלתה פגיעות בשרתי Apache. כתובת C2: 1.2.3.4. דומיין זדוני: sub.evil.org</description>
      <link>https://www.gov.il/he/alerts/123</link>
      <pubDate>Fri, 26 Jun 2026 10:00:00 +0300</pubDate>
    </item>
    <item>
      <title>Malware campaign uses hash aaaa1234bbbb5678cccc9012dddd3456eeee7890ffff1234aaaa5678bbbb9012</title>
      <description>File hash detected. URL: https://sub.evil.org/payload?x=1</description>
      <link>https://www.gov.il/he/alerts/124</link>
      <pubDate>Thu, 25 Jun 2026 14:00:00 +0300</pubDate>
    </item>
  </channel>
</rss>"""


def _reload_modules(tmp_path, monkeypatch):
    """Reload _utils + cert_il_feed with isolated cache dir."""
    monkeypatch.setenv("SENTINEL_STATE_DIR", str(tmp_path))
    import importlib

    import _utils
    import cert_il_feed

    importlib.reload(_utils)
    importlib.reload(cert_il_feed)
    return cert_il_feed


class TestCertILFeed:
    def test_fetch_and_parse(self, tmp_path, monkeypatch):
        """Feed fetcher parses RSS and extracts IOCs from alert text."""
        cert_il_feed = _reload_modules(tmp_path, monkeypatch)

        mock_resp = MagicMock()
        mock_resp.content = _SAMPLE_RSS.encode("utf-8")
        mock_resp.raise_for_status = MagicMock()

        with patch.object(cert_il_feed.requests, "get", return_value=mock_resp):
            result = cert_il_feed.cert_il_feed()

        assert result["available"] is True
        assert result["alerts_count"] == 2
        alerts = result["alerts"]
        assert "CVE-2024-1234" in alerts[0]["title"] or "Apache" in alerts[0]["title"]
        assert alerts[0]["link"] == "https://www.gov.il/he/alerts/123"

    def test_ioc_extraction_from_alerts(self, tmp_path, monkeypatch):
        """IOCs are extracted from alert title+summary and merged."""
        cert_il_feed = _reload_modules(tmp_path, monkeypatch)

        mock_resp = MagicMock()
        mock_resp.content = _SAMPLE_RSS.encode("utf-8")
        mock_resp.raise_for_status = MagicMock()

        with patch.object(cert_il_feed.requests, "get", return_value=mock_resp):
            result = cert_il_feed.cert_il_feed()

        all_iocs = result["all_iocs"]
        assert "CVE-2024-1234" in all_iocs["cves"]
        assert "1.2.3.4" in all_iocs["ips_v4"]
        assert "sub.evil.org" in all_iocs["domains"]
        assert any("sub.evil.org/payload" in u for u in all_iocs["urls"])
        # SHA256 hash from second alert
        assert any(len(h) == 64 for h in all_iocs["hashes"])

    def test_per_alert_iocs(self, tmp_path, monkeypatch):
        """Each alert has its own 'iocs' key with extracted indicators."""
        cert_il_feed = _reload_modules(tmp_path, monkeypatch)

        mock_resp = MagicMock()
        mock_resp.content = _SAMPLE_RSS.encode("utf-8")
        mock_resp.raise_for_status = MagicMock()

        with patch.object(cert_il_feed.requests, "get", return_value=mock_resp):
            result = cert_il_feed.cert_il_feed()

        alert0 = result["alerts"][0]
        assert "iocs" in alert0
        assert "CVE-2024-1234" in alert0["iocs"]["cves"]
        assert "1.2.3.4" in alert0["iocs"]["ips_v4"]

    def test_fetch_failure_returns_unavailable(self, tmp_path, monkeypatch):
        """Network failure returns structured error, not exception."""
        cert_il_feed = _reload_modules(tmp_path, monkeypatch)

        with patch.object(cert_il_feed.requests, "get", side_effect=ConnectionError("DNS failed")):
            result = cert_il_feed.cert_il_feed()

        assert result["available"] is False
        assert "Fetch failed" in result["error"]

    def test_empty_feed(self, tmp_path, monkeypatch):
        """Feed with no entries returns available=True, alerts=[]."""
        cert_il_feed = _reload_modules(tmp_path, monkeypatch)

        empty_rss = b"""<?xml version="1.0"?>
<rss version="2.0"><channel><title>Empty</title></channel></rss>"""

        mock_resp = MagicMock()
        mock_resp.content = empty_rss
        mock_resp.raise_for_status = MagicMock()

        with patch.object(cert_il_feed.requests, "get", return_value=mock_resp):
            result = cert_il_feed.cert_il_feed()

        assert result["available"] is True
        assert result["alerts"] == []
        assert result["alerts_count"] == 0

    def test_caching(self, tmp_path, monkeypatch):
        """Second call within TTL returns cached result (no HTTP call)."""
        cert_il_feed = _reload_modules(tmp_path, monkeypatch)

        mock_resp = MagicMock()
        mock_resp.content = _SAMPLE_RSS.encode("utf-8")
        mock_resp.raise_for_status = MagicMock()

        with patch.object(cert_il_feed.requests, "get", return_value=mock_resp) as mock_get:
            cert_il_feed.cert_il_feed()
            assert mock_get.call_count == 1
            # Second call should hit cache
            cert_il_feed.cert_il_feed()
            assert mock_get.call_count == 1  # No new HTTP call


class TestCmdCertIL:
    def test_markdown_render(self, tmp_path, monkeypatch):
        """cmd_cert_il renders Markdown with alerts + IOCs."""
        cert_il_feed = _reload_modules(tmp_path, monkeypatch)
        import importlib

        import intel_commands

        importlib.reload(intel_commands)

        mock_resp = MagicMock()
        mock_resp.content = _SAMPLE_RSS.encode("utf-8")
        mock_resp.raise_for_status = MagicMock()

        with patch.object(cert_il_feed.requests, "get", return_value=mock_resp):
            output = intel_commands.cmd_cert_il("markdown")

        assert "CERT-IL" in output
        assert "CVE-2024-1234" in output
        assert "1.2.3.4" in output
        assert "sub.evil.org" in output
        assert "gov.il" in output  # source URL or link

    def test_json_render(self, tmp_path, monkeypatch):
        """cmd_cert_il with json format returns valid JSON."""
        cert_il_feed = _reload_modules(tmp_path, monkeypatch)
        import importlib

        import intel_commands

        importlib.reload(intel_commands)

        mock_resp = MagicMock()
        mock_resp.content = _SAMPLE_RSS.encode("utf-8")
        mock_resp.raise_for_status = MagicMock()

        with patch.object(cert_il_feed.requests, "get", return_value=mock_resp):
            output = intel_commands.cmd_cert_il("json")

        parsed = json.loads(output)
        assert parsed["available"] is True
        assert parsed["alerts_count"] == 2

    def test_failure_render(self, tmp_path, monkeypatch):
        """cmd_cert_il renders error message on fetch failure."""
        cert_il_feed = _reload_modules(tmp_path, monkeypatch)
        import importlib

        import intel_commands

        importlib.reload(intel_commands)

        with patch.object(cert_il_feed.requests, "get", side_effect=ConnectionError("DNS")):
            output = intel_commands.cmd_cert_il("markdown")

        assert "❌" in output
        assert "CERT-IL" in output
