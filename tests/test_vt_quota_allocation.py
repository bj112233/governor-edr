# tests/test_vt_quota_allocation.py
"""Tests for _allocate_quota — VirusTotal quota allocation (pure function).

Validates:
1. Hash priority: first hash gets full_intel
2. Domain priority: first domain gets full_intel
3. IP priority: first 2 IPs get full_intel
4. Overflow IOCs get fallback_only
5. Empty inputs return empty dict
6. Mixed IOC types respect priority order
7. Total full_intel slots never exceed 4
"""

from services.pre_hunt_enricher import _allocate_quota


def test_empty_inputs():
    """Empty lists → empty allocation dict."""
    result = _allocate_quota([], [], [])
    assert result == {}


def test_single_hash_gets_full_intel():
    """A single hash should get full_intel (highest priority)."""
    result = _allocate_quota([], [], ["a1b2c3d4e5f6"])
    assert result["a1b2c3d4e5f6"] == "full_intel"


def test_single_domain_gets_full_intel():
    """A single domain should get full_intel."""
    result = _allocate_quota([], ["evil.com"], [])
    assert result["evil.com"] == "full_intel"


def test_single_ip_gets_full_intel():
    """A single IP should get full_intel."""
    result = _allocate_quota(["8.8.8.8"], [], [])
    assert result["8.8.8.8"] == "full_intel"


def test_hash_priority_over_domain_and_ip():
    """Hash should get full_intel before domain and IP."""
    result = _allocate_quota(["1.2.3.4"], ["evil.com"], ["abc123"])
    assert result["abc123"] == "full_intel"
    assert result["evil.com"] == "full_intel"
    assert result["1.2.3.4"] == "full_intel"


def test_overflow_hash_gets_fallback():
    """Second hash (overflow) should get fallback_only."""
    result = _allocate_quota([], [], ["hash1", "hash2"])
    assert result["hash1"] == "full_intel"
    assert result["hash2"] == "fallback_only"


def test_overflow_domain_gets_fallback():
    """Second domain (overflow) should get fallback_only."""
    result = _allocate_quota([], ["domain1.com", "domain2.com"], [])
    assert result["domain1.com"] == "full_intel"
    assert result["domain2.com"] == "fallback_only"


def test_overflow_ip_gets_fallback():
    """Third IP (overflow) should get fallback_only."""
    result = _allocate_quota(["1.1.1.1", "2.2.2.2", "3.3.3.3"], [], [])
    assert result["1.1.1.1"] == "full_intel"
    assert result["2.2.2.2"] == "full_intel"
    assert result["3.3.3.3"] == "fallback_only"


def test_mixed_iocs_priority_order():
    """Mixed: 2 hashes + 2 domains + 2 IPs — priority Hash > Domain > IP."""
    result = _allocate_quota(
        ips=["ip1", "ip2", "ip3"],
        domains=["dom1", "dom2"],
        hashes=["hash1", "hash2"],
    )
    # Hash: 1 slot full_intel, 1 overflow
    assert result["hash1"] == "full_intel"
    assert result["hash2"] == "fallback_only"
    # Domain: 1 slot full_intel, 1 overflow
    assert result["dom1"] == "full_intel"
    assert result["dom2"] == "fallback_only"
    # IP: 2 slots full_intel (remaining after hash+domain = 4-1-1=2), 1 overflow
    assert result["ip1"] == "full_intel"
    assert result["ip2"] == "full_intel"
    assert result["ip3"] == "fallback_only"


def test_full_intel_never_exceeds_4():
    """Total full_intel allocations must never exceed 4 (VT quota)."""
    result = _allocate_quota(
        ips=["ip1", "ip2", "ip3", "ip4", "ip5"],
        domains=["dom1", "dom2", "dom3"],
        hashes=["hash1", "hash2", "hash3"],
    )
    full_intel_count = sum(1 for v in result.values() if v == "full_intel")
    assert full_intel_count <= 4


def test_all_iocs_allocated():
    """Every IOC must appear in the allocation dict."""
    ips = ["ip1", "ip2"]
    domains = ["dom1"]
    hashes = ["hash1"]
    result = _allocate_quota(ips, domains, hashes)
    for ioc in ips + domains + hashes:
        assert ioc in result
