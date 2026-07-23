#!/usr/bin/env python3
"""PCAP Analyst — streaming network capture analysis for IOC extraction.

OOM-hardened: PcapReader generator (never rdpcap), 50MB file gate,
port-filtered at read layer (UDP/53 + TCP/443 only), set()-based dedup.

Commands:
  analyze --path FILE  — full summary (DNS queries + TLS SNI)
  dns     --path FILE  — DNS queries + answers only
  sni     --path FILE  — TLS SNI values only
  iocs    --path FILE  — IOC JSON for intel-skill chaining (--chain to auto-enrich)
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from _dns_extractor import DnsCollector
from _ioc_extractor import aggregate_to_iocs, render_ioc_json
from _parsers import check_file_size, iter_filtered_packets
from _tls_extractor import SniCollector

_MAX_DISPLAY = 50  # cap per-category display to protect 16K token budget


def _run_single_pass(path: str, want_dns: bool, want_tls: bool) -> tuple[dict, dict]:
    """Single streaming pass — feeds each packet to relevant collector(s)."""
    dns_collector = DnsCollector() if want_dns else None
    tls_collector = SniCollector() if want_tls else None
    total_packets = 0

    for packet, kind in iter_filtered_packets(path):
        total_packets += 1
        if kind == "dns" and dns_collector:
            dns_collector.feed(packet)
        elif kind == "tls" and tls_collector:
            tls_collector.feed(packet)

    dns_result = dns_collector.result() if dns_collector else {"queries": set(), "answers": set(), "packet_count": 0}
    tls_result = tls_collector.result() if tls_collector else {"sni": set(), "packet_count": 0}
    dns_result["_total_packets"] = total_packets
    return dns_result, tls_result


def _format_set(items: set[str], label: str, limit: int = _MAX_DISPLAY) -> list[str]:
    """Format a set as sorted lines with truncation notice."""
    lines = [f"**{label} ({len(items)} unique):**"]
    if not items:
        lines.append("  (none found)")
        return lines
    for item in sorted(items)[:limit]:
        lines.append(f"  - {item}")
    if len(items) > limit:
        lines.append(f"  ... and {len(items) - limit} more (use `iocs` command for full list)")
    return lines


def cmd_analyze(path: str) -> str:
    """Full summary — DNS + TLS in a single pass."""
    dns_result, tls_result = _run_single_pass(path, want_dns=True, want_tls=True)
    total = dns_result.get("_total_packets", 0)
    lines = [
        f"=== PCAP Analysis: {path} ===",
        f"Packets scanned (filtered DNS/TLS): {total}",
        f"  DNS packets: {dns_result['packet_count']}",
        f"  TLS packets: {tls_result['packet_count']}",
        "",
    ]
    lines.extend(_format_set(dns_result["queries"], "DNS Queries"))
    lines.append("")
    lines.extend(_format_set(dns_result["answers"], "DNS Answers"))
    lines.append("")
    lines.extend(_format_set(tls_result["sni"], "TLS SNI (Server Names)"))
    return "\n".join(lines)


def cmd_dns(path: str) -> str:
    """DNS-only view."""
    dns_result, _ = _run_single_pass(path, want_dns=True, want_tls=False)
    lines = [f"=== DNS Analysis: {path} ===", f"DNS packets: {dns_result['packet_count']}", ""]
    lines.extend(_format_set(dns_result["queries"], "Queries"))
    lines.append("")
    lines.extend(_format_set(dns_result["answers"], "Answers"))
    return "\n".join(lines)


def cmd_sni(path: str) -> str:
    """TLS SNI-only view."""
    _, tls_result = _run_single_pass(path, want_dns=False, want_tls=True)
    lines = [f"=== TLS SNI Analysis: {path} ===", f"TLS packets: {tls_result['packet_count']}", ""]
    lines.extend(_format_set(tls_result["sni"], "Server Name Indication"))
    return "\n".join(lines)


def cmd_iocs(path: str, chain: bool) -> str:
    """IOC JSON output for intel-skill chaining."""
    dns_result, tls_result = _run_single_pass(path, want_dns=True, want_tls=True)
    iocs = aggregate_to_iocs(dns_result, tls_result)
    json_out = render_ioc_json(iocs)
    if chain:
        stats = iocs["stats"]
        triage = iocs.get("triage", "")
        return (
            f"=== IOCs extracted from {path} ===\n"
            f"Raw: {stats['raw_domains']} domains + {stats['raw_ips']} IPs"
            f" → Filtered: {stats['filtered_domains']}d + {stats['filtered_ips']}i"
            f" → Selected: {stats['selected_total']} for enrichment\n"
            f"DNS packets: {stats['dns_packets']} | TLS packets: {stats['tls_packets']}"
            f"{triage}\n\n"
            f"**Chain to intel-skill:**\n"
            f"```json\n{json_out}\n```"
        )
    return json_out


def main() -> int:
    parser = argparse.ArgumentParser(description="PCAP Analyst — streaming IOC extraction")
    parser.add_argument("command", choices=["analyze", "dns", "sni", "iocs"], help="Analysis mode")
    parser.add_argument("--path", required=True, help="Path to .pcap/.pcapng file")
    parser.add_argument("--chain", action="store_true", help="Format as chainable IOC JSON for intel-skill")
    args = parser.parse_args()

    # ── 50MB hard gate ──
    size_err = check_file_size(args.path)
    if size_err:
        print(size_err, file=sys.stderr)
        return 1

    try:
        if args.command == "analyze":
            print(cmd_analyze(args.path))
        elif args.command == "dns":
            print(cmd_dns(args.path))
        elif args.command == "sni":
            print(cmd_sni(args.path))
        elif args.command == "iocs":
            print(cmd_iocs(args.path, args.chain))
    except FileNotFoundError:
        print(f"❌ File not found: {args.path}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"❌ PCAP parse error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
