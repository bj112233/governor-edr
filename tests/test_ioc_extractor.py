"""Tests for the expanded IOC extractor (URL/CIDR/ASN/Email + legacy).

Validates that new entity types are extracted, deduped, and validated
(prefix range, trailing-punctuation stripping, case normalization).
"""

from services.ioc_extractor import extract_all


class TestLegacyIOCs:
    """Pre-existing IOC types must still extract correctly."""

    def test_ipv4(self):
        out = extract_all("connect to 1.2.3.4 then 10.0.0.1")
        assert "1.2.3.4" in out["ips_v4"]
        assert "10.0.0.1" in out["ips_v4"]

    def test_ipv6(self):
        out = extract_all("addr 2001:db8::1 reachable")
        assert any("2001:db8::1" in v for v in out["ips_v6"])

    def test_hash_sha256(self):
        h = "a" * 64
        out = extract_all(f"sample {h} flagged")
        assert h in out["hashes"]

    def test_cve_uppercased(self):
        out = extract_all("see cve-2024-1234 and CVE-2024-9999")
        assert "CVE-2024-1234" in out["cves"]
        assert "CVE-2024-9999" in out["cves"]

    def test_domain(self):
        # Note: 2-part .com/.net/.org domains are filtered by _BAD_DOMAINS
        # (pre-existing behavior). Use 3-part or non-blocked TLD.
        out = extract_all("host sub.example.org and tracker.example.xyz")
        assert "sub.example.org" in out["domains"]
        assert "tracker.example.xyz" in out["domains"]

    def test_empty_text(self):
        out = extract_all("")
        assert out["ips_v4"] == []
        assert out["urls"] == []
        assert out["cidrs"] == []
        assert out["asns"] == []
        assert out["emails"] == []


class TestURLExtraction:
    def test_simple_url(self):
        out = extract_all("visit https://evil.com/path")
        assert "https://evil.com/path" in out["urls"]

    def test_url_with_query_params_not_truncated(self):
        out = extract_all("redirect https://evil.com/x?id=1&token=abc")
        urls = out["urls"]
        assert any("id=1" in u and "token=abc" in u for u in urls), urls

    def test_url_trailing_punctuation_stripped(self):
        out = extract_all("see https://evil.com/path.")
        assert "https://evil.com/path" in out["urls"]
        assert "https://evil.com/path." not in out["urls"]

    def test_url_trailing_paren_stripped(self):
        out = extract_all("(see https://evil.com/path)")
        assert "https://evil.com/path" in out["urls"]

    def test_url_dedup(self):
        out = extract_all("https://evil.com/a https://evil.com/a")
        assert out["urls"].count("https://evil.com/a") == 1

    def test_http_scheme(self):
        out = extract_all("go http://example.com")
        assert "http://example.com" in out["urls"]


class TestCIDRExtraction:
    def test_valid_cidr(self):
        out = extract_all("block 10.0.0.0/8 and 192.168.1.0/24")
        assert "10.0.0.0/8" in out["cidrs"]
        assert "192.168.1.0/24" in out["cidrs"]

    def test_cidr_prefix_zero(self):
        out = extract_all("route 0.0.0.0/0")
        assert "0.0.0.0/0" in out["cidrs"]

    def test_cidr_prefix_max(self):
        out = extract_all("host 1.2.3.4/32")
        assert "1.2.3.4/32" in out["cidrs"]

    def test_cidr_invalid_prefix_rejected(self):
        out = extract_all("bogus 10.0.0.0/33")
        assert "10.0.0.0/33" not in out["cidrs"]

    def test_cidr_dedup(self):
        out = extract_all("10.0.0.0/8 10.0.0.0/8")
        assert out["cidrs"].count("10.0.0.0/8") == 1


class TestASNExtraction:
    def test_asn_uppercased(self):
        out = extract_all("routed via as15169 and AS32934")
        assert "AS15169" in out["asns"]
        assert "AS32934" in out["asns"]

    def test_asn_dedup(self):
        out = extract_all("AS15169 as15169")
        assert out["asns"].count("AS15169") == 1

    def test_asn_not_confused_with_word(self):
        out = extract_all("the word ASSET is not an ASN")
        assert all("ASSET" not in a for a in out["asns"])


class TestEmailExtraction:
    def test_simple_email(self):
        out = extract_all("contact admin@evil.com")
        assert "admin@evil.com" in out["emails"]

    def test_email_with_plus(self):
        out = extract_all("reach user+tag@example.org")
        assert "user+tag@example.org" in out["emails"]

    def test_email_dedup(self):
        out = extract_all("a@b.com a@b.com")
        assert out["emails"].count("a@b.com") == 1


class TestMixedExtraction:
    def test_all_types_in_one_text(self):
        text = (
            "Alert: host sub.evil.org (AS15169) at 1.2.3.4/32 "
            "serving https://sub.evil.org/payload?x=1 "
            "contact admin@evil.xyz "
            "CVE-2024-1234 sample " + "a" * 64
        )
        out = extract_all(text)
        assert "sub.evil.org" in out["domains"]
        assert "AS15169" in out["asns"]
        assert "1.2.3.4/32" in out["cidrs"]
        assert any("sub.evil.org/payload" in u for u in out["urls"])
        assert "admin@evil.xyz" in out["emails"]
        assert "CVE-2024-1234" in out["cves"]
        assert ("a" * 64) in out["hashes"]

    def test_url_with_query_preserved(self):
        """URL query parameters must not be truncated (spec requirement)."""
        out = extract_all("https://sub.evil.org/p?id=1&token=abc")
        urls = out["urls"]
        assert any("id=1" in u and "token=abc" in u for u in urls), urls
