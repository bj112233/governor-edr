"""Firewall Skill — unified Windows Firewall management CLI.

Subcommands:
  block   --ip <ip>           Add SENTINEL_BLOCK_<ip> rule (inbound + outbound).
  unblock --ip <ip>           Remove the SENTINEL_BLOCK_<ip> rule.
  list                        Show all active SENTINEL_BLOCK_* rules.
  drops   [--count N]         Tail recent DROP events from pfirewall.log.
  stats                       Aggregate counters (active blocks, last drop, etc).

Designed to replace the in-process tools `block_ip`, `unblock_ip`,
`get_firewall_drops`. Mirrors their security model (IP regex, in+out rules,
SENTINEL_BLOCK_* naming convention) so behavior is bit-for-bit equivalent.

Command implementations extracted to focused modules:
- firewall_state.py:     constants, audit, whitelist, utilities
- firewall_backends.py:  FirewallBackend ABC, NetshBackend, NetSecurityBackend
- firewall_commands.py:  block, unblock, block-cidr, whitelist, sweep, audit, drops, stats
- firewall_list.py:      list (PowerShell JSON + netsh text parsers)
"""
from __future__ import annotations

import argparse
import sys

from firewall_backends import _get_backend
from firewall_commands import (
    cmd_audit,
    cmd_block,
    cmd_block_cidr,
    cmd_block_port,
    cmd_drops,
    cmd_list,
    cmd_stats,
    cmd_sweep,
    cmd_unblock,
    cmd_unblock_port,
    cmd_whitelist,
)


def main() -> int:
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception as exc:
            print(f"[WARN] stdout reconfigure failed: {exc}", file=sys.stderr)

    parser = argparse.ArgumentParser(prog="firewall.py")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_block = sub.add_parser("block")
    p_block.add_argument("--ip", required=True)
    p_block.add_argument(
        "--duration",
        help="Auto-unblock duration (e.g. 30s, 15m, 24h, 7d). "
        "Run 'firewall.py sweep' periodically to expire entries.",
    )
    p_block.add_argument("--reason", default="")

    p_unblock = sub.add_parser("unblock")
    p_unblock.add_argument("--ip", required=True)

    p_cidr = sub.add_parser("block-cidr")
    p_cidr.add_argument("--network", required=True, help="CIDR like 10.0.0.0/24")
    p_cidr.add_argument("--reason", default="")

    p_bport = sub.add_parser("block-port")
    p_bport.add_argument("--port", type=int, required=True, help="Port number (1-65535)")
    p_bport.add_argument("--protocol", choices=["TCP", "UDP", "tcp", "udp"], default="TCP")
    p_bport.add_argument("--reason", default="")

    p_uport = sub.add_parser("unblock-port")
    p_uport.add_argument("--port", type=int, required=True, help="Port number to unblock")
    p_uport.add_argument("--protocol", choices=["TCP", "UDP", "tcp", "udp"], default="TCP")

    p_wl = sub.add_parser("whitelist")
    p_wl.add_argument("--action", choices=["list", "add", "remove"], required=True)
    p_wl.add_argument("--ip", help="IP or CIDR (required for add/remove)")

    p_audit = sub.add_parser("audit")
    p_audit.add_argument("--count", type=int, default=20)

    sub.add_parser("sweep")
    sub.add_parser("list")

    p_drops = sub.add_parser("drops")
    p_drops.add_argument("--count", type=int, default=20)

    sub.add_parser("stats")

    parser.add_argument(
        "--backend",
        choices=["netsh", "powershell"],
        default="netsh",
        help="Firewall backend engine (default: netsh)",
    )

    args = parser.parse_args()
    backend = _get_backend(args.backend)

    try:
        if args.cmd == "block":
            out = cmd_block(backend, args.ip, duration=args.duration, reason=args.reason)
        elif args.cmd == "unblock":
            out = cmd_unblock(backend, args.ip)
        elif args.cmd == "block-cidr":
            out = cmd_block_cidr(backend, args.network, reason=args.reason)
        elif args.cmd == "block-port":
            out = cmd_block_port(backend, args.port, protocol=args.protocol, reason=args.reason)
        elif args.cmd == "unblock-port":
            out = cmd_unblock_port(backend, args.port, protocol=args.protocol)
        elif args.cmd == "whitelist":
            out = cmd_whitelist(args.action, args.ip)
        elif args.cmd == "audit":
            out = cmd_audit(args.count)
        elif args.cmd == "sweep":
            out = cmd_sweep(backend)
        elif args.cmd == "list":
            out = cmd_list(backend)
        elif args.cmd == "drops":
            out = cmd_drops(backend, args.count)
        elif args.cmd == "stats":
            out = cmd_stats(backend)
        else:
            parser.print_help()
            return 2
    except (OSError, PermissionError) as exc:
        # Read-only queries: a missing log / lack of admin rights is an EXPECTED
        # environmental condition, not a tool malfunction. Returning a hard error
        # (exit 3) trips the agent circuit breaker AND poisons crash-lesson memory,
        # permanently penalizing this tool in the ToolRanker. Degrade gracefully.
        _READ_ONLY = {"list", "drops", "stats", "audit"}
        if args.cmd in _READ_ONLY:
            print(f"ℹ️ נתוני חומת אש אינם זמינים ({args.cmd}): {exc}. ייתכן שנדרשות הרשאות אדמין או הפעלת logging.")
            return 0
        print(f"❌ ERROR: Firewall command '{args.cmd}' failed: {exc}. Do not retry with this tool.")
        return 3
    except Exception as exc:
        import traceback

        traceback.print_exc(file=sys.stderr)
        print(f"❌ ERROR: Firewall command '{args.cmd}' crashed unexpectedly: {exc}. Do not retry with this tool.")
        return 3

    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
