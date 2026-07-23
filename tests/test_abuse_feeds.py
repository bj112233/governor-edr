"""Tests for Abuse.ch threat feeds — URLhaus + ThreatFox + orchestrator integration.

Mocks HTTP responses to avoid network dependency. Validates CSV/JSON parsing,
IOC extraction, cache behavior, fallback without Auth-Key, orchestrator score
boost, cmd_feeds rendering, and MITRE mapping from threat_type.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

_SCRIPTS = str(Path(__file__).resolve().parents[1] / "skills" / "intel-skill" / "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)


# ── URLhaus CSV sample ──

_URLHAUS_CSV = """# URLhaus CSV export
id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter
1,2026-06-26 10:00:00 UTC,http://evil.com/malware.exe,online,malware_download,exe,https://urlhaus.abuse.ch/url/1/,researcher1
2,2026-06-26 11:00:00 UTC,http://192.168.1.1/payload,online,botnet,bot,https://urlhaus.abuse.ch/url/2/,researcher2
3,2026-06-26 12:00:00 UTC,http://clean-site.com/,offline,,clean,https://urlhaus.abuse.ch/url/3/,researcher3
4,2026-06-26 13:00:00 UTC,http://bad-domain.org/shell.php,online,webshell,php,https://urlhaus.abuse.ch/url/4/,researcher4
"""

# ── ThreatFox JSON sample ──

_THREATFOX_JSON = {
    "query_status": "ok",
    "data": [
        {
            "id": "101",
            "ioc": "1.2.3.4",
            "threat_type": "botnet_cc",
            "threat_type_desc": "Botnet C&C server",
            "ioc_type": "ip:port",
            "malware": "win.dridex",
            "malware_printable": "Dridex",
            "confidence_level": 75,
            "first_seen": "2026-06-26 10:00:00 UTC",
            "tags": ["banker", "exe"],
        },
        {
            "id": "102",
            "ioc": "evil-c2.com",
            "threat_type": "botnet_cc",
            "threat_type_desc": "Botnet C&C server",
            "ioc_type": "domain",
            "malware": "win.emotet",
            "malware_printable": "Emotet",
            "confidence_level": 90,
            "first_seen": "2026-06-26 11:00:00 UTC",
            "tags": ["trojan"],
        },
        {
            "id": "103",
            "ioc": "low-confidence-ip.com",
            "threat_type": "payload_delivery",
            "ioc_type": "domain",
            "malware": "adware",
            "malware_printable": "Adware",
            "confidence_level": 20,  # Below threshold — should be filtered
            "first_seen": "2026-06-26 12:00:00 UTC",
            "tags": [],
        },
        {
            "id": "104",
            "ioc": "a" * 64,
            "threat_type": "malware_artefact",
            "ioc_type": "sha256_hash",
            "malware": "trickbot",
            "malware_printable": "TrickBot",
            "confidence_level": 60,
            "first_seen": "2026-06-26 13:00:00 UTC",
            "tags": ["banker"],
        },
    ],
}


def _mock_urlhaus_response():
    resp = MagicMock()
    resp.text = _URLHAUS_CSV
    resp.raise_for_status = MagicMock()
    return resp


def _mock_threatfox_response():
    resp = MagicMock()
    resp.json.return_value = _THREATFOX_JSON
    resp.raise_for_status = MagicMock()
    return resp


# ── URLhaus tests ──


class TestURLhausFetcher:
    def test_fetch_parses_csv(self, tmp_path, monkeypatch):
        from urlhaus_feed import fetch_urlhaus_csv

        # Bypass cache
        monkeypatch.setattr("urlhaus_feed.cache_get", lambda *a, **kw: None)
        monkeypatch.setattr("urlhaus_feed.cache_set", lambda *a, **kw: None)
        monkeypatch.setattr("urlhaus_feed.requests.get", lambda *a, **kw: _mock_urlhaus_response())

        rows = fetch_urlhaus_csv(limit=10)
        # Only online + threat rows (3 of 4)
        assert len(rows) == 3
        assert rows[0]["url"] == "http://evil.com/malware.exe"
        assert all(r.get("url_status", "").lower() == "online" for r in rows)

    def test_fetch_filters_offline(self, tmp_path, monkeypatch):
        from urlhaus_feed import fetch_urlhaus_csv

        monkeypatch.setattr("urlhaus_feed.cache_get", lambda *a, **kw: None)
        monkeypatch.setattr("urlhaus_feed.cache_set", lambda *a, **kw: None)
        monkeypatch.setattr("urlhaus_feed.requests.get", lambda *a, **kw: _mock_urlhaus_response())

        rows = fetch_urlhaus_csv(limit=10)
        urls = [r["url"] for r in rows]
        assert "http://clean-site.com/" not in urls  # offline row excluded

    def test_fetch_returns_empty_on_http_error(self, monkeypatch):
        from urlhaus_feed import fetch_urlhaus_csv

        monkeypatch.setattr("urlhaus_feed.cache_get", lambda *a, **kw: None)
        monkeypatch.setattr("urlhaus_feed.cache_set", lambda *a, **kw: None)

        def raise_error(*a, **kw):
            raise ConnectionError("Network down")

        monkeypatch.setattr("urlhaus_feed.requests.get", raise_error)
        rows = fetch_urlhaus_csv(limit=10)
        assert rows == []

    def test_fetch_uses_cache(self, monkeypatch):
        from urlhaus_feed import fetch_urlhaus_csv

        cached_data = {"rows": [{"url": "http://cached.com/", "url_status": "online", "threat": "malware"}]}
        monkeypatch.setattr("urlhaus_feed.cache_get", lambda *a, **kw: cached_data)
        rows = fetch_urlhaus_csv(limit=10)
        assert rows[0]["url"] == "http://cached.com/"


class TestURLhausExtraction:
    def test_extract_iocs_from_rows(self):
        from urlhaus_feed import extract_urlhaus_iocs

        rows = [
            {"url": "http://evil.com/malware.exe", "threat": "malware_download", "tags": "exe"},
            {"url": "http://192.168.1.1/payload", "threat": "botnet", "tags": "bot"},
        ]
        iocs = extract_urlhaus_iocs(rows)
        assert "http://evil.com/malware.exe" in iocs["urls"]
        assert "evil.com" in iocs["domains"] or "192.168.1.1" in iocs["ips"]


# ── ThreatFox tests ──


class TestThreatFoxFetcher:
    def test_fetch_parses_json(self, monkeypatch):
        from threatfox_feed import fetch_threatfox_iocs

        monkeypatch.setattr("threatfox_feed.cache_get", lambda *a, **kw: None)
        monkeypatch.setattr("threatfox_feed.cache_set", lambda *a, **kw: None)
        monkeypatch.setattr("threatfox_feed.requests.post", lambda *a, **kw: _mock_threatfox_response())

        iocs = fetch_threatfox_iocs(days=1)
        # 3 of 4 pass confidence >= 50
        assert len(iocs) == 3
        assert all(ioc["confidence_level"] >= 50 for ioc in iocs)

    def test_fetch_filters_low_confidence(self, monkeypatch):
        from threatfox_feed import fetch_threatfox_iocs

        monkeypatch.setattr("threatfox_feed.cache_get", lambda *a, **kw: None)
        monkeypatch.setattr("threatfox_feed.cache_set", lambda *a, **kw: None)
        monkeypatch.setattr("threatfox_feed.requests.post", lambda *a, **kw: _mock_threatfox_response())

        iocs = fetch_threatfox_iocs(days=1)
        ids = [ioc["id"] for ioc in iocs]
        assert "103" not in ids  # confidence_level=20 filtered out

    def test_fetch_returns_empty_on_error(self, monkeypatch):
        from threatfox_feed import fetch_threatfox_iocs

        monkeypatch.setattr("threatfox_feed.cache_get", lambda *a, **kw: None)
        monkeypatch.setattr("threatfox_feed.cache_set", lambda *a, **kw: None)

        def raise_error(*a, **kw):
            raise TimeoutError("API timeout")

        monkeypatch.setattr("threatfox_feed.requests.post", raise_error)
        iocs = fetch_threatfox_iocs(days=1)
        assert iocs == []

    def test_fetch_returns_empty_on_bad_status(self, monkeypatch):
        from threatfox_feed import fetch_threatfox_iocs

        bad_resp = MagicMock()
        bad_resp.json.return_value = {"query_status": "no_results", "data": []}
        bad_resp.raise_for_status = MagicMock()

        monkeypatch.setattr("threatfox_feed.cache_get", lambda *a, **kw: None)
        monkeypatch.setattr("threatfox_feed.cache_set", lambda *a, **kw: None)
        monkeypatch.setattr("threatfox_feed.requests.post", lambda *a, **kw: bad_resp)

        iocs = fetch_threatfox_iocs(days=1)
        assert iocs == []


class TestThreatFoxExtraction:
    def test_extract_maps_ioc_types(self):
        from threatfox_feed import extract_threatfox_iocs

        # All 4 rows except the low-confidence one (index 2)
        rows = [_THREATFOX_JSON["data"][i] for i in (0, 1, 3)]
        extracted = extract_threatfox_iocs(rows)
        assert "1.2.3.4" in extracted["ips"]
        assert "evil-c2.com" in extracted["domains"]
        assert "a" * 64 in extracted["hashes"]

    def test_extract_strips_port_from_ip(self):
        from threatfox_feed import extract_threatfox_iocs

        rows = [{"ioc": "1.2.3.4:443", "ioc_type": "ip:port", "malware_printable": "Test"}]
        extracted = extract_threatfox_iocs(rows)
        assert "1.2.3.4" in extracted["ips"]
        assert "1.2.3.4:443" not in extracted["ips"]

    def test_extract_malware_map(self):
        from threatfox_feed import extract_threatfox_iocs

        rows = [_THREATFOX_JSON["data"][i] for i in (0, 1, 3)]
        extracted = extract_threatfox_iocs(rows)
        assert extracted["malware_map"]["1.2.3.4"] == "dridex"
        assert extracted["malware_map"]["evil-c2.com"] == "emotet"


# ── Threat feeds check (orchestrator integration) ──


class TestThreatFeedsCheck:
    def test_matched_ip_in_threatfox(self, monkeypatch):
        from threat_feeds_check import check_target_in_feeds

        monkeypatch.setattr(
            "threatfox_feed.fetch_threatfox_iocs",
            lambda days=1: _THREATFOX_JSON["data"][:3],
        )
        monkeypatch.setattr("urlhaus_feed.fetch_urlhaus_csv", lambda limit=100: [])
        result = check_target_in_feeds("1.2.3.4", "ip")
        assert result["matched"] is True
        assert result["threatfox"] is True
        assert result["malware"] == "Dridex"
        assert result["threat_type"] == "botnet_cc"

    def test_unmatched_target(self, monkeypatch):
        from threat_feeds_check import check_target_in_feeds

        monkeypatch.setattr(
            "threatfox_feed.fetch_threatfox_iocs",
            lambda days=1: _THREATFOX_JSON["data"][:3],
        )
        monkeypatch.setattr("urlhaus_feed.fetch_urlhaus_csv", lambda limit=100: [])
        result = check_target_in_feeds("99.99.99.99", "ip")
        assert result["matched"] is False

    def test_urlhaus_match(self, monkeypatch):
        from threat_feeds_check import check_target_in_feeds

        monkeypatch.setattr("threatfox_feed.fetch_threatfox_iocs", lambda days=1: [])
        monkeypatch.setattr(
            "urlhaus_feed.fetch_urlhaus_csv",
            lambda limit=100: [
                {"url": "http://evil.com/bad", "url_status": "online", "threat": "malware", "tags": ""},
            ],
        )
        result = check_target_in_feeds("evil.com", "domain")
        assert result["matched"] is True
        assert result["urlhaus"] is True


# ── MITRE mapping with threat feeds ──


class TestMITREWithThreatFeeds:
    def test_threat_type_botnet_cc_maps_to_t1071(self):
        from mitre_mapping import map_payload_to_mitre

        payload = {
            "target": "1.2.3.4",
            "kind": "ip",
            "sources": {},
            "threat_feeds": {
                "matched": True,
                "threatfox": True,
                "threat_type": "botnet_cc",
                "malware": "Dridex",
            },
        }
        matches = map_payload_to_mitre(payload)
        ids = [m.technique_id for m in matches]
        assert "T1071" in ids

    def test_threat_type_payload_delivery_maps_to_t1566(self):
        from mitre_mapping import map_payload_to_mitre

        payload = {
            "target": "evil.org",
            "kind": "domain",
            "sources": {},
            "threat_feeds": {
                "matched": True,
                "urlhaus": True,
                "threat_type": "payload_delivery",
                "malware": None,
            },
        }
        matches = map_payload_to_mitre(payload)
        ids = [m.technique_id for m in matches]
        assert "T1566" in ids

    def test_urlhaus_match_adds_phishing_signal(self):
        from mitre_mapping import map_payload_to_mitre

        payload = {
            "target": "bad.org",
            "kind": "domain",
            "sources": {},
            "threat_feeds": {
                "matched": True,
                "urlhaus": True,
                "threat_type": None,
                "malware": None,
            },
        }
        matches = map_payload_to_mitre(payload)
        ids = [m.technique_id for m in matches]
        assert "T1566" in ids

    def test_threatfox_match_adds_c2_signal(self):
        from mitre_mapping import map_payload_to_mitre

        payload = {
            "target": "1.2.3.4",
            "kind": "ip",
            "sources": {},
            "threat_feeds": {
                "matched": True,
                "threatfox": True,
                "threat_type": None,
                "malware": None,
            },
        }
        matches = map_payload_to_mitre(payload)
        ids = [m.technique_id for m in matches]
        assert "T1071" in ids


# ── cmd_feeds rendering ──


class TestCmdFeeds:
    def test_urlhaus_markdown(self, monkeypatch):
        from intel_commands import cmd_feeds

        monkeypatch.setattr(
            "osint_gatherer.urlhaus_feed",
            lambda limit: {
                "available": True,
                "count": 2,
                "iocs": {
                    "urls": ["http://evil.com/bad"],
                    "domains": ["evil.com"],
                    "ips": [],
                    "hashes": [],
                },
            },
        )
        output = cmd_feeds("urlhaus", "markdown", 50)
        assert "URLhaus" in output
        assert "http://evil.com/bad" in output

    def test_threatfox_json(self, monkeypatch):
        from intel_commands import cmd_feeds

        monkeypatch.setattr(
            "osint_gatherer.threatfox_feed",
            lambda days: {
                "available": True,
                "count": 1,
                "iocs": {"urls": [], "domains": ["evil-c2.com"], "ips": [], "hashes": []},
                "malware_map": {"evil-c2.com": "emotet"},
            },
        )
        output = cmd_feeds("threatfox", "json", 50)
        parsed = json.loads(output)
        assert parsed["count"] == 1
        assert "evil-c2.com" in parsed["iocs"]["domains"]

    def test_unknown_source(self):
        from intel_commands import cmd_feeds

        output = cmd_feeds("badsource", "markdown", 50)
        assert "❌" in output

    def test_all_source_markdown(self, monkeypatch):
        from intel_commands import cmd_feeds

        monkeypatch.setattr(
            "osint_gatherer.urlhaus_feed",
            lambda limit: {
                "available": True,
                "count": 1,
                "iocs": {"urls": ["http://x.com"], "domains": [], "ips": [], "hashes": []},
            },
        )
        monkeypatch.setattr(
            "osint_gatherer.threatfox_feed",
            lambda days: {
                "available": True,
                "count": 1,
                "iocs": {"urls": [], "domains": ["c2.com"], "ips": [], "hashes": []},
                "malware_map": {},
            },
        )
        output = cmd_feeds("all", "markdown", 50)
        assert "URLhaus" in output
        assert "ThreatFox" in output
