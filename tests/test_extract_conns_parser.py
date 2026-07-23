# tests/test_extract_conns_parser.py
"""Regression test: _extract_conns parser was grabbing the first parenthesized
group (org/ASN) instead of the last (proc_name:pid), causing all proc_names
to be 'unknown'.

Line format: '[ip]:port (org / AS123) (proc_name:pid)'
                    ^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^
                    first group      last group (correct)
"""

from services.monitor_analyzer import SnapshotDiffer


def test_extract_conns_dual_parens():
    """Line with both (org/ASN) and (proc:pid) → extract proc from LAST group."""
    lines = ["[52.168.117.170]:443 (Microsoft / AS8075) (msteamsupdate.exe:12345)"]
    conns = SnapshotDiffer._extract_conns(lines)
    assert len(conns) == 1
    ip, proc, port, pid = list(conns)[0]
    assert ip == "52.168.117.170"
    assert proc == "msteamsupdate.exe"  # NOT "unknown"
    assert port == 443
    assert pid == 12345


def test_extract_conns_ipv6_dual_parens():
    """IPv6 line with both groups."""
    lines = ["[2603:1063:2001:3203::365:ff1]:443 (Microsoft / AS8075) (svchost.exe:678)"]
    conns = SnapshotDiffer._extract_conns(lines)
    assert len(conns) == 1
    ip, proc, port, pid = list(conns)[0]
    assert "2603:1063" in ip
    assert proc == "svchost.exe"
    assert port == 443
    assert pid == 678


def test_extract_conns_single_parens():
    """Line with only (proc:pid) — backward compat."""
    lines = ["[1.2.3.4]:443 (chrome.exe:999)"]
    conns = SnapshotDiffer._extract_conns(lines)
    assert len(conns) == 1
    ip, proc, port, pid = list(conns)[0]
    assert ip == "1.2.3.4"
    assert proc == "chrome.exe"
    assert port == 443
    assert pid == 999


def test_extract_conns_unknown_provider():
    """Line with 'unknown provider' as org and (proc:pid)."""
    lines = ["[10.0.0.1]:80 (unknown provider) (python.exe:42)"]
    conns = SnapshotDiffer._extract_conns(lines)
    assert len(conns) == 1
    ip, proc, port, pid = list(conns)[0]
    assert proc == "python.exe"
    assert pid == 42


def test_extract_conns_no_parens_skipped():
    """Line without parens → skipped."""
    lines = ["1.2.3.4:443 no parens here"]
    conns = SnapshotDiffer._extract_conns(lines)
    assert len(conns) == 0


def test_extract_conns_empty():
    """Empty list → empty set."""
    assert SnapshotDiffer._extract_conns([]) == set()
    assert SnapshotDiffer._extract_conns([""]) == set()
