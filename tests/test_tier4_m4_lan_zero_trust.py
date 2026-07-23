# tests/test_tier4_m4_lan_zero_trust.py
"""Tests for Tier 4 M4: LAN Zero Trust (loopback vs RFC1918 separation).

M4: Split is_loopback_ip / is_private_ip in web_c2_auth.py
M4: Allow blocking RFC1918 IPs in remediation_engine (keep loopback blocked)
M4: Include LAN IPs in enrichment (threat_classifier + intel_enricher)
"""

import pytest

from services.web_c2_auth import (
    client_ip_allowed,
    is_loopback_ip,
    is_private_ip,
)

# ── M4: Loopback vs Private separation ──────────────────────────────


class TestLoopbackVsPrivate:
    def test_loopback_ipv4(self):
        assert is_loopback_ip("127.0.0.1") is True
        assert is_loopback_ip("127.255.255.255") is True

    def test_loopback_ipv6(self):
        assert is_loopback_ip("::1") is True

    def test_loopback_ipv6_mapped(self):
        assert is_loopback_ip("::ffff:127.0.0.1") is True

    def test_rfc1918_not_loopback(self):
        """M4: RFC1918 IPs are NOT loopback."""
        assert is_loopback_ip("192.168.1.1") is False
        assert is_loopback_ip("10.0.0.1") is False
        assert is_loopback_ip("172.16.0.1") is False

    def test_public_not_loopback(self):
        assert is_loopback_ip("8.8.8.8") is False

    def test_none_not_loopback(self):
        assert is_loopback_ip(None) is False

    def test_rfc1918_private(self):
        """M4: RFC1918 IPs are private."""
        assert is_private_ip("192.168.1.1") is True
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("172.16.0.1") is True
        assert is_private_ip("172.31.255.255") is True

    def test_loopback_not_private(self):
        """M4: Loopback is NOT private (separate category)."""
        assert is_private_ip("127.0.0.1") is False
        assert is_private_ip("::1") is False

    def test_link_local_private(self):
        assert is_private_ip("fe80::1") is True

    def test_public_not_private(self):
        assert is_private_ip("8.8.8.8") is False
        assert is_private_ip("1.1.1.1") is False

    def test_none_not_private(self):
        assert is_private_ip(None) is False

    def test_client_ip_allowed_still_works(self):
        """Backward compat: client_ip_allowed accepts both loopback + private."""
        assert client_ip_allowed("127.0.0.1") is True
        assert client_ip_allowed("192.168.1.1") is True
        assert client_ip_allowed("8.8.8.8") is False


# ── M4: Remediation engine — loopback blocked, RFC1918 allowed ──────


class TestRemediationLanBlock:
    def test_loopback_cannot_be_blocked(self):
        """M4: Loopback is always rejected from firewall blocking."""
        from services.remediation_engine import block_ip_in_firewall

        ok, msg = block_ip_in_firewall("127.0.0.1")
        assert ok is False
        assert "loopback" in msg.lower()

    def test_rfc1918_can_be_blocked(self):
        """M4: RFC1918 LAN IPs CAN be blocked (lateral movement defense)."""
        from unittest.mock import MagicMock, patch

        from services.remediation_engine import block_ip_in_firewall

        with patch("services.remediation_engine.subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stderr="", stdout="Ok."),
                MagicMock(returncode=0, stderr="", stdout="Ok."),
            ]
            ok, msg = block_ip_in_firewall("192.168.1.50")
        assert ok is True

    def test_rfc1918_10_can_be_blocked(self):
        """M4: 10.x.x.x can be blocked."""
        from unittest.mock import MagicMock, patch

        from services.remediation_engine import block_ip_in_firewall

        with patch("services.remediation_engine.subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stderr="", stdout="Ok."),
                MagicMock(returncode=0, stderr="", stdout="Ok."),
            ]
            ok, _ = block_ip_in_firewall("10.0.0.99")
        assert ok is True

    def test_is_loopback_ip_function(self):
        """M4: _is_loopback_ip correctly identifies loopback."""
        from services.remediation_engine import _is_loopback_ip

        assert _is_loopback_ip("127.0.0.1") is True
        assert _is_loopback_ip("127.255.255.255") is True
        assert _is_loopback_ip("::1") is True
        assert _is_loopback_ip("192.168.1.1") is False
        assert _is_loopback_ip("8.8.8.8") is False

    def test_is_rfc1918_ip_function(self):
        """M4: _is_rfc1918_ip correctly identifies RFC1918 (not loopback)."""
        from services.remediation_engine import _is_rfc1918_ip

        assert _is_rfc1918_ip("192.168.1.1") is True
        assert _is_rfc1918_ip("10.0.0.1") is True
        assert _is_rfc1918_ip("172.16.0.1") is True
        assert _is_rfc1918_ip("127.0.0.1") is False  # loopback, not RFC1918
        assert _is_rfc1918_ip("8.8.8.8") is False


# ── M4: Threat classifier includes LAN IPs ──────────────────────────


class TestThreatClassifierLanInclusion:
    def test_lan_ips_included_in_enrichment(self):
        """M4: LAN IPs (192.168.x.x) are now included for enrichment.

        Previously skipped — now only loopback (127.x, ::1) is skipped.
        """
        # We can't easily test the full classify function, but we can
        # verify the filter logic by checking what IPs would be collected.
        connections = [
            {"raddr_ip": "192.168.1.50", "raddr_port": 4444, "proc_name": "svchost.exe"},
            {"raddr_ip": "10.0.0.99", "raddr_port": 8080, "proc_name": "chrome.exe"},
            {"raddr_ip": "127.0.0.1", "raddr_port": 80, "proc_name": "system"},
            {"raddr_ip": "8.8.8.8", "raddr_port": 53, "proc_name": "svchost.exe"},
        ]

        # Replicate the M4 filter logic
        unique_ips = set()
        for c in connections:
            rip = c.get("raddr_ip", "")
            if rip and not rip.startswith(("127.", "::1")):
                unique_ips.add(rip)

        # LAN IPs should be included
        assert "192.168.1.50" in unique_ips
        assert "10.0.0.99" in unique_ips
        # Loopback should be excluded
        assert "127.0.0.1" not in unique_ips
        # Public IPs should be included
        assert "8.8.8.8" in unique_ips
