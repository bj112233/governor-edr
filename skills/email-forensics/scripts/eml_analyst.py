#!/usr/bin/env python3
"""EML Analyst — phishing & email forensics for IOC extraction.

Parses .eml (stdlib) and .msg (extract-msg) files. Extracts:
  - SPF/DKIM/DMARC verdicts from Authentication-Results
  - Received chain (routing path: who→whom)
  - Key forensic headers (From, Reply-To, Return-Path, X-Originating-IP)
  - URLs + IPs + emails from body
  - IOC JSON for intel-skill chaining

Commands:
  headers --path FILE  — all forensically relevant headers
  auth    --path FILE  — SPF/DKIM/DMARC verdicts only
  route   --path FILE  — Received chain (routing path)
  urls    --path FILE  — URLs/IPs/emails from body
  full    --path FILE  — complete analysis (--chain for intel-skill JSON)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from _body_extractor import extract_body, extract_urls_and_ips
from _header_parser import (
    get_key_headers,
    load_message,
    parse_auth_results,
    parse_received_chain,
)
from _msg_reader import is_msg_available, load_msg

# ── Dynamic sys.path injection for _shared/ioc_triage ──
# scripts/ → email-forensics/ → skills/ → _shared/
_SHARED_DIR = str(Path(__file__).resolve().parent.parent.parent / "_shared")
if _SHARED_DIR not in sys.path:
    sys.path.insert(0, _SHARED_DIR)

from ioc_triage import (  # noqa: E402
    filter_benign_domains,
    filter_private_ips,
    generate_triage_report,
    top_k_triage,
)

_MAX_DISPLAY = 30  # cap per-category display to protect 16K token budget
_TOP_K = 15  # aligns with VT rate limit (4 req/min → ~4 min background processing)


def _load_any(path: str) -> dict[str, Any]:
    """Load .eml or .msg file. Returns a normalized dict."""
    suffix = Path(path).suffix.lower()
    if suffix == ".msg":
        return load_msg(path)
    # .eml (default for any other extension too)
    msg = load_message(path)
    return {
        "msg_obj": msg,
        "subject": msg.get("Subject", ""),
        "sender": msg.get("From", ""),
    }


def cmd_headers(path: str) -> str:
    """All forensically relevant headers."""
    data = _load_any(path)
    if "error" in data:
        return data["error"]
    if "msg_obj" in data:
        headers = get_key_headers(data["msg_obj"])
    else:
        headers = data.get("headers", {})

    lines = [f"=== Email Headers: {path} ==="]
    for key, value in headers.items():
        lines.append(f"  {key}: {value}")
    if not headers:
        lines.append("  (no headers found)")
    return "\n".join(lines)


def cmd_auth(path: str) -> str:
    """SPF/DKIM/DMARC verdicts."""
    data = _load_any(path)
    if "error" in data:
        return data["error"]
    if "msg_obj" in data:
        auth = parse_auth_results(data["msg_obj"])
    else:
        # .msg — try to parse from headers dict
        auth_headers = data.get("headers", {}).get("Authentication-Results", "")
        auth = _parse_auth_from_string(auth_headers)

    verdict_icon = {"pass": "✅", "fail": "❌", "none": "⚠️", "softfail": "⚠️"}
    lines = [
        f"=== Authentication Results: {path} ===",
        f"  SPF:   {verdict_icon.get(auth['spf'], '?')} {auth['spf']}",
        f"  DKIM:  {verdict_icon.get(auth['dkim'], '?')} {auth['dkim']}",
        f"  DMARC: {verdict_icon.get(auth['dmarc'], '?')} {auth['dmarc']}",
        "",
        f"  Raw: {auth['raw'][:200]}",
    ]
    return "\n".join(lines)


def _parse_auth_from_string(text: str) -> dict[str, Any]:
    """Fallback auth parser for .msg files (no email.Message object)."""
    import re

    spf = "none"
    dkim = "none"
    dmarc = "none"
    if text:
        m = re.search(r"spf=(\w+)", text, re.IGNORECASE)
        if m:
            spf = m.group(1).lower()
        m = re.search(r"dkim=(\w+)", text, re.IGNORECASE)
        if m:
            dkim = m.group(1).lower()
        m = re.search(r"dmarc=(\w+)", text, re.IGNORECASE)
        if m:
            dmarc = m.group(1).lower()
    return {"spf": spf, "dkim": dkim, "dmarc": dmarc, "raw": text[:500] or "(none)"}


def cmd_route(path: str) -> str:
    """Received chain — routing path (oldest first)."""
    data = _load_any(path)
    if "error" in data:
        return data["error"]
    if "msg_obj" not in data:
        return "⚠️ Route analysis not available for .msg files (no Received chain)."
    hops = parse_received_chain(data["msg_obj"])
    lines = [f"=== Routing Path: {path} ===", f"Hops: {len(hops)}", ""]
    for i, hop in enumerate(hops, 1):
        lines.append(f"  Hop {i}: {hop['from']} → {hop['by']}")
        if hop["for"]:
            lines.append(f"          for: {hop['for']}")
        lines.append(f"          date: {hop['date']}")
    if not hops:
        lines.append("  (no Received headers)")
    return "\n".join(lines)


def cmd_urls(path: str) -> str:
    """URLs/IPs/emails from body."""
    data = _load_any(path)
    if "error" in data:
        return data["error"]
    if "msg_obj" in data:
        body = extract_body(data["msg_obj"])
        combined = body["text"] + "\n" + body["html_as_text"]
    else:
        combined = data.get("body", "")

    iocs = extract_urls_and_ips(combined)
    lines = [f"=== Body IOCs: {path} ===", ""]

    lines.append(f"**URLs ({len(iocs['urls'])}):**")
    for url in iocs["urls"][:_MAX_DISPLAY]:
        lines.append(f"  - {url}")
    if len(iocs["urls"]) > _MAX_DISPLAY:
        lines.append(f"  ... and {len(iocs['urls']) - _MAX_DISPLAY} more")

    lines.append(f"\n**IPs ({len(iocs['ips'])}):**")
    for ip in iocs["ips"][:_MAX_DISPLAY]:
        lines.append(f"  - {ip}")

    lines.append(f"\n**Email addresses ({len(iocs['emails'])}):**")
    for em in iocs["emails"][:_MAX_DISPLAY]:
        lines.append(f"  - {em}")

    return "\n".join(lines)


def cmd_full(path: str, chain: bool) -> str:
    """Complete analysis — headers + auth + route + URLs + IOC JSON."""
    data = _load_any(path)
    if "error" in data:
        return data["error"]

    sections = [cmd_headers(path), "", cmd_auth(path), "", cmd_route(path), "", cmd_urls(path)]

    if "msg_obj" in data:
        body = extract_body(data["msg_obj"])
        combined = body["text"] + "\n" + body["html_as_text"]
    else:
        combined = data.get("body", "")
    iocs = extract_urls_and_ips(combined)

    # Build IOC JSON for intel-skill — with triage filtering
    raw_domains = set()
    raw_ips = set(iocs["ips"])
    for url in iocs["urls"]:
        # Extract domain from URL
        from urllib.parse import urlparse

        parsed = urlparse(url)
        if parsed.hostname and not _is_ip(parsed.hostname):
            raw_domains.add(parsed.hostname)
        elif parsed.hostname and _is_ip(parsed.hostname):
            raw_ips.add(parsed.hostname)

    # ── Triage: deterministic filtering before enrichment ──
    original_count = len(raw_domains) + len(raw_ips)
    filtered_ips = filter_private_ips(sorted(raw_ips))
    filtered_domains = filter_benign_domains(sorted(raw_domains))
    filtered_count = len(filtered_domains) + len(filtered_ips)

    # Top-K selection (frequency=1 for all since extraction is set-based)
    ip_counts = {ip: 1 for ip in filtered_ips}
    domain_counts = {d: 1 for d in filtered_domains}
    selected_ips = top_k_triage(ip_counts, k=_TOP_K)
    selected_domains = top_k_triage(domain_counts, k=_TOP_K)
    selected_count = len(selected_ips) + len(selected_domains)

    triage_report = generate_triage_report(original_count, filtered_count, selected_count)

    ioc_json = {
        "iocs": {
            "domains": selected_domains,
            "ips": selected_ips,
            "urls": iocs["urls"][:_TOP_K],  # cap URLs too
            "hashes": [],
        },
        "source": "email-forensics",
        "chain_to": "intel-skill",
        "stats": {
            "urls": len(iocs["urls"]),
            "raw_domains": len(raw_domains),
            "raw_ips": len(raw_ips),
            "filtered_domains": len(filtered_domains),
            "filtered_ips": len(filtered_ips),
            "selected_total": selected_count,
        },
        "triage": triage_report,
    }

    if chain:
        sections.append("")
        sections.append(f"=== IOC JSON for intel-skill ===")
        sections.append(f"```json\n{json.dumps(ioc_json, ensure_ascii=False, separators=(',', ':'))}\n```")
    else:
        sections.append("")
        sections.append(json.dumps(ioc_json, ensure_ascii=False, separators=(",", ":")))

    return "\n".join(sections)


def _is_ip(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="EML Analyst — phishing & email forensics")
    parser.add_argument("command", choices=["headers", "auth", "route", "urls", "full"], help="Analysis mode")
    parser.add_argument("--path", required=True, help="Path to .eml or .msg file")
    parser.add_argument("--chain", action="store_true", help="Format output as chainable IOC JSON for intel-skill")
    args = parser.parse_args()

    if not Path(args.path).exists():
        print(f"❌ File not found: {args.path}", file=sys.stderr)
        return 1

    # Warn if .msg requested but extract-msg not installed
    if Path(args.path).suffix.lower() == ".msg" and not is_msg_available():
        print(
            "⚠️ .msg support requires 'extract-msg' package. Install: pip install extract-msg",
            file=sys.stderr,
        )

    try:
        if args.command == "headers":
            print(cmd_headers(args.path))
        elif args.command == "auth":
            print(cmd_auth(args.path))
        elif args.command == "route":
            print(cmd_route(args.path))
        elif args.command == "urls":
            print(cmd_urls(args.path))
        elif args.command == "full":
            print(cmd_full(args.path, args.chain))
    except Exception as exc:
        print(f"❌ EML parse error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
