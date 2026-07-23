# tests/test_skill_smoke_all.py
r"""Smoke test: call all 15 skills in sequence with a safe command each.

Verifies every skill loads, accepts a command, and returns a non-error
response within a reasonable timeout. Measures per-skill latency.

Run: .\.venv\Scripts\python.exe -m pytest tests/test_skill_smoke_all.py -v -s
"""

import asyncio
import json
import re
import time
from pathlib import Path

import pytest

from services.skills_engine import get_skills_engine

# Safe, non-destructive command + args for each skill
# Chosen to be read-only, fast, and not require external API keys where possible
_SKILL_PROBES: list[tuple[str, str, str]] = [
    ("crypto-skill", "uuid", "{}"),
    ("currency-skill", "run", '{"from":"USD","to":"ILS","amount":1}'),
    ("email-forensics", "auth", "__EML_PATH__"),
    ("file-analyst", "stats", '{"path":".gitignore"}'),
    ("firewall-skill", "list", "{}"),
    ("geocode-skill", "forward", '{"address":"Tel Aviv"}'),
    ("intel-skill", "ip", '{"target":"8.8.8.8"}'),
    ("news-monitor", "tech_ai", "{}"),
    ("pcap-analyst", "analyze", "__PCAP_PATH__"),
    ("persistence-hunter", "scan", "{}"),
    ("report-maker", "default", '{"stdin":true,"title":"Smoke Test"}'),
    ("stocks-skill", "quote", '{"symbol":"AAPL"}'),
    ("translator-skill", "run", '{"text":"hello","to":"he"}'),
    ("weather-skill", "run", '{"location":"Tel Aviv"}'),
    ("web-scraper", "fetch", '{"url":"https://example.com"}'),
]


def _strip_emoji(text: str) -> str:
    """Remove emoji/surrogate chars that Windows cp1255 can't encode."""
    return re.sub(r"[^\x20-\x7e\n\r\t]", "?", text)


def _ensure_pcap_fixture() -> str:
    """Create a minimal .pcap fixture for pcap-analyst smoke test if missing.

    Returns the ABSOLUTE path (skills run with cwd=skill dir, so relative
    paths from project root would fail).
    """
    fixture = Path("tests/fixtures/smoke.pcap").resolve()
    if fixture.exists():
        return str(fixture)
    fixture.parent.mkdir(parents=True, exist_ok=True)
    from scapy.all import DNS, DNSQR, IP, UDP, Ether, wrpcap

    pkt = Ether() / IP(dst="8.8.8.8") / UDP(dport=53) / DNS(id=1, qd=DNSQR(qname="example.com"))
    wrpcap(str(fixture), [pkt])
    return str(fixture)


def _ensure_eml_fixture() -> str:
    """Create a minimal .eml fixture for email-forensics smoke test if missing.

    Returns the ABSOLUTE path (skills run with cwd=skill dir).
    """
    fixture = Path("tests/fixtures/phishing.eml").resolve()
    if fixture.exists():
        return str(fixture)
    fixture.parent.mkdir(parents=True, exist_ok=True)
    from email.message import EmailMessage

    msg = EmailMessage()
    msg["From"] = "test@example.com"
    msg["To"] = "victim@example.com"
    msg["Subject"] = "Smoke Test"
    msg["Authentication-Results"] = "spf=pass dkim=pass dmarc=pass"
    msg.set_content("Test body with URL: https://example.com/login")
    fixture.write_bytes(bytes(msg))
    return str(fixture)


@pytest.mark.asyncio
async def test_all_skills_smoke():
    """Call all 15 skills in sequence. Log latency + pass/fail."""
    pcap_path = _ensure_pcap_fixture()
    eml_path = _ensure_eml_fixture()
    engine = get_skills_engine()
    await engine.load_async()

    results: list[dict] = []
    for skill_name, command, args in _SKILL_PROBES:
        if args == "__PCAP_PATH__":
            args = json.dumps({"path": pcap_path})
        elif args == "__EML_PATH__":
            args = json.dumps({"path": eml_path})
        t0 = time.perf_counter()
        try:
            response = await asyncio.wait_for(
                engine.execute(skill_name, command, args),
                timeout=30.0,
            )
            dt = time.perf_counter() - t0
            ok = (
                "error" not in response[:80].lower()
                and "not found" not in response[:80].lower()
                and "failed" not in response[:80].lower()
                and len(response) > 5
            )
            results.append(
                {
                    "skill": skill_name,
                    "command": command,
                    "ok": ok,
                    "latency_ms": round(dt * 1000, 0),
                    "preview": response[:80].replace("\n", " "),
                }
            )
            print(
                f"  {'PASS' if ok else 'FAIL'} {skill_name:20s} {command:12s} "
                f"{dt * 1000:7.0f}ms | {_strip_emoji(response[:60])}"
            )
        except TimeoutError:
            dt = time.perf_counter() - t0
            results.append(
                {
                    "skill": skill_name,
                    "command": command,
                    "ok": False,
                    "latency_ms": round(dt * 1000, 0),
                    "preview": "TIMEOUT",
                }
            )
            print(f"  FAIL {skill_name:20s} {command:12s} {dt * 1000:7.0f}ms | TIMEOUT")
        except Exception as exc:
            dt = time.perf_counter() - t0
            results.append(
                {
                    "skill": skill_name,
                    "command": command,
                    "ok": False,
                    "latency_ms": round(dt * 1000, 0),
                    "preview": str(exc)[:80],
                }
            )
            print(f"  FAIL {skill_name:20s} {command:12s} {dt * 1000:7.0f}ms | {_strip_emoji(str(exc)[:60])}")

    passed = sum(1 for r in results if r["ok"])
    failed = len(results) - passed
    total_ms = sum(r["latency_ms"] for r in results)
    print(f"\nSmoke Test: {passed}/{len(results)} passed, {failed} failed, {total_ms}ms total")

    # At least 13/15 must pass (allow 2 failures for network-dependent skills)
    assert passed >= 13, f"Only {passed}/{len(results)} skills passed (need >= 13)"
