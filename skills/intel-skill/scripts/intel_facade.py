"""Intel Skill — Orchestrator Facade.

Receives commands from LLM/user, delegates to:
  - osint_gatherer  (external APIs)
  - data_enrichment (local context)
  - threat_scoring  (math engine)

Renders results to Markdown or JSON.

Command implementations extracted to focused modules:
- intel_sweep.py:    cmd_sweep (F(52)→A(4) via 7 helpers)
- intel_commands.py: cmd_dns, cmd_whois, cmd_israeli_monitor, cmd_cert_il, cmd_cluster
"""
from __future__ import annotations

import argparse
import json
import sys

from orchestrator import IntelOrchestrator
from renderer import IntelRenderer

# Shared stateless singletons (3a.1 refactor)
_orchestrator = IntelOrchestrator()
_renderer = IntelRenderer()

from intel_commands import (  # noqa: E402
    cmd_attack,
    cmd_cert_il,
    cmd_dns,
    cmd_feeds,
    cmd_whois,
)
from intel_commands import (
    cmd_cluster as _cmd_cluster_impl,
)
from intel_commands import (
    cmd_israeli_monitor as _cmd_israeli_impl,
)
from intel_sweep import cmd_sweep  # noqa: E402

# ─────────────── Commands ───────────────


def cmd_ip(target: str, fmt: str) -> str:
    payload = _orchestrator.analyze_ip(target)
    if fmt == "json":
        return json.dumps(payload, ensure_ascii=False, indent=2)
    return _renderer.render(payload)


def cmd_domain(target: str, fmt: str) -> str:
    payload = _orchestrator.analyze_domain(target)
    if fmt == "json":
        return json.dumps(payload, ensure_ascii=False, indent=2)
    return _renderer.render(payload)


def cmd_hash(target: str, fmt: str) -> str:
    payload = _orchestrator.analyze_hash(target)
    if fmt == "json":
        return json.dumps(payload, ensure_ascii=False, indent=2)
    return _renderer.render(payload)


def cmd_israeli_monitor(target: str, fmt: str) -> str:
    return _cmd_israeli_impl(target, fmt, render_fn=_renderer.render)


def cmd_cluster(targets: list[str], threshold: float, fmt: str) -> str:
    return _cmd_cluster_impl(targets, threshold, fmt, cmd_ip, cmd_domain, cmd_hash)


def _render(payload: dict) -> str:
    """Backward-compat shim. Rendering logic now lives in renderer.IntelRenderer."""
    return _renderer.render(payload)


# ─────────────── Entry point ───────────────


def main() -> int:
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception as exc:
            print(f"[WARN] stdout reconfigure failed: {exc}", file=sys.stderr)

    parser = argparse.ArgumentParser(prog="intel.py")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("ip", "domain", "hash", "dns", "whois"):
        p = sub.add_parser(name)
        p.add_argument("--target", required=True)
        p.add_argument("--format", choices=["markdown", "json"], default="markdown")

    p_sweep = sub.add_parser("sweep")
    p_sweep.add_argument("--threshold", type=int, default=10, help="Minimum score to flag (default: 10)")
    p_sweep.add_argument("--format", choices=["markdown", "json"], default="markdown")

    p_israeli = sub.add_parser("israeli")
    p_israeli.add_argument("--target", required=True)
    p_israeli.add_argument("--format", choices=["markdown", "json"], default="markdown")

    p_cert = sub.add_parser("cert")
    p_cert.add_argument("--format", choices=["markdown", "json"], default="markdown")

    p_cluster = sub.add_parser("cluster")
    p_cluster.add_argument("--targets", required=True, help="Comma-separated IOC list (IPs, domains, hashes)")
    p_cluster.add_argument("--threshold", type=float, default=0.80, help="Cosine similarity threshold (default: 0.80)")
    p_cluster.add_argument("--format", choices=["markdown", "json"], default="markdown")

    p_attack = sub.add_parser("attack")
    p_attack.add_argument("--technique", required=True, help="MITRE ATT&CK technique ID (e.g. T1059)")
    p_attack.add_argument("--format", choices=["markdown", "json"], default="json")

    p_feeds = sub.add_parser("feeds")
    p_feeds.add_argument("--source", required=True, choices=["urlhaus", "threatfox", "all"],
                         help="Threat feed source")
    p_feeds.add_argument("--limit", type=int, default=50, help="Max IOCs to display (default: 50)")
    p_feeds.add_argument("--format", choices=["markdown", "json"], default="markdown")

    args = parser.parse_args()
    fmt = args.format
    target = getattr(args, "target", None)

    dispatch = {
        "ip": cmd_ip, "domain": cmd_domain, "hash": cmd_hash,
        "dns": cmd_dns, "whois": cmd_whois, "sweep": cmd_sweep,
        "israeli": cmd_israeli_monitor, "cert": cmd_cert_il, "cluster": cmd_cluster,
        "attack": cmd_attack, "feeds": cmd_feeds,
    }

    try:
        if args.cmd == "cert":
            print(dispatch[args.cmd](fmt))
        elif args.cmd == "cluster":
            targets = [t.strip() for t in args.targets.split(",") if t.strip()]
            print(dispatch[args.cmd](targets, args.threshold, fmt))
        elif args.cmd == "sweep":
            print(dispatch[args.cmd](args.threshold, fmt))
        elif args.cmd == "attack":
            print(dispatch[args.cmd](args.technique, fmt))
        elif args.cmd == "feeds":
            print(dispatch[args.cmd](args.source, fmt, args.limit))
        else:
            print(dispatch[args.cmd](target, fmt))
    except (OSError, ConnectionError, TimeoutError) as exc:
        print(f"❌ ERROR: Intel command '{args.cmd}' failed: {exc}. Do not retry with this tool.")
        return 3
    except Exception as exc:
        import traceback

        traceback.print_exc(file=sys.stderr)
        print(f"❌ ERROR: Intel command '{args.cmd}' crashed unexpectedly: {exc}. Do not retry with this tool.")
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
