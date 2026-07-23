# tests/test_monitor_helpers.py
"""Tests for monitor_engine_helpers pure-logic functions.

Covers: is_browser_connection, _is_known_good_asn, _format_connection.
No mocking needed — pure logic.
"""

from services.monitor_engine_helpers import (
    _BROWSER_PROCS,
    _KNOWN_GOOD_ASNS,
    _format_connection,
    _is_known_good_asn,
    _is_messaging_xmpp_to_facebook,
    is_browser_connection,
)


class TestIsBrowserConnection:
    def test_chrome_on_443(self):
        assert is_browser_connection("chrome.exe", 443) is True

    def test_firefox_on_80(self):
        assert is_browser_connection("firefox.exe", 80) is True

    def test_non_browser_on_443(self):
        assert is_browser_connection("malware.exe", 443) is False

    def test_browser_on_non_web_port(self):
        assert is_browser_connection("chrome.exe", 22) is False

    def test_case_insensitive(self):
        assert is_browser_connection("CHROME.EXE", 443) is True

    def test_edge_on_8080(self):
        assert is_browser_connection("msedge.exe", 8080) is True


class TestIsKnownGoodAsn:
    def test_google_asn(self):
        assert _is_known_good_asn("15169", None) is True

    def test_cloudflare_asn(self):
        assert _is_known_good_asn("13335", None) is True

    def test_asn_with_prefix(self):
        assert _is_known_good_asn("AS15169", None) is True

    def test_unknown_asn(self):
        assert _is_known_good_asn("99999", None) is False

    def test_known_org(self):
        assert _is_known_good_asn(None, "Google LLC") is True

    def test_known_org_aws(self):
        assert _is_known_good_asn(None, "Amazon AWS") is True

    def test_unknown_org(self):
        assert _is_known_good_asn(None, "Evil Corp") is False

    def test_both_none(self):
        assert _is_known_good_asn(None, None) is False

    def test_both_known(self):
        assert _is_known_good_asn("15169", "Google") is True


class TestFormatConnection:
    def test_ipv4_format(self):
        cache = {"1.2.3.4": {"asn": "15169", "org": "Google"}}
        result = _format_connection("1.2.3.4", 443, 1234, "chrome.exe", cache)
        assert "1.2.3.4:443" in result
        assert "Google" in result
        assert "AS15169" in result

    def test_no_enrichment(self):
        result = _format_connection("5.6.7.8", 80, None, "unknown.exe", {})
        assert "5.6.7.8:80" in result
        assert "unknown provider" in result

    def test_only_org(self):
        cache = {"1.2.3.4": {"asn": None, "org": "Microsoft"}}
        result = _format_connection("1.2.3.4", 443, 100, "app.exe", cache)
        assert "Microsoft" in result
        assert "AS" not in result.split("Microsoft")[1]  # no AS part

    def test_only_asn(self):
        cache = {"1.2.3.4": {"asn": "13335", "org": None}}
        result = _format_connection("1.2.3.4", 443, 100, "app.exe", cache)
        assert "AS13335" in result


class TestIsMessagingXmppToFacebook:
    """Regression coverage for the WhatsApp/Facebook XMPP alert-bleed fix.

    Real-world false positive: net:threat_suspicious fired for proc="unknown"
    -> port 5222 -> 2a03:2880:f242:1c2:face:b00c:0:167 (Facebook AS32934)
    because ip-api.com enrichment failed for that IPv6 address, leaving
    asn/org both None. The static IPv6 CIDR fallback must catch this case.
    """

    def test_non_xmpp_port_never_matches(self):
        assert _is_messaging_xmpp_to_facebook(443, "32934", "Facebook, Inc.") is False

    def test_matches_by_asn(self):
        assert _is_messaging_xmpp_to_facebook(5222, "32934", None) is True
        assert _is_messaging_xmpp_to_facebook(5222, "AS32934", None) is True

    def test_matches_by_org(self):
        assert _is_messaging_xmpp_to_facebook(5222, None, "Facebook, Inc.") is True
        assert _is_messaging_xmpp_to_facebook(5222, None, "Meta Platforms") is True

    def test_no_enrichment_falls_back_to_ipv6_cidr(self):
        """The exact IP from the real alert, with enrichment unavailable."""
        assert _is_messaging_xmpp_to_facebook(5222, None, None, ip="2a03:2880:f242:1c2:face:b00c:0:167") is True

    def test_no_enrichment_and_non_facebook_ip_stays_suspicious(self):
        assert _is_messaging_xmpp_to_facebook(5222, None, None, ip="2001:4860:4860::8888") is False

    def test_no_enrichment_no_ip_stays_suspicious(self):
        assert _is_messaging_xmpp_to_facebook(5222, None, None) is False

    def test_malformed_ip_does_not_raise(self):
        assert _is_messaging_xmpp_to_facebook(5222, None, None, ip="not-an-ip") is False
