"""
CLI entry point — orchestrate parse → resolve → dispatch → cluster → output.

This module wires together the small ``_cli_*`` helpers that were extracted
from the original monolithic ``main()`` to keep each file ≤300 lines and
each function within the project's CC threshold.
"""

import sys
from pathlib import Path

from _cli_actions import process_file
from _cli_cluster import cluster_results
from _cli_output import write_output
from _cli_parser import build_parser
from _cli_paths import resolve_arg_paths
from _cli_schema import adapt_mcp_schema


def _collect_results(args, effective_action: str):
    """Gather (path, content) tuples for the requested --path / --dir / batch."""
    results = []
    if args.action == "batch":
        if not args.dir:
            print("❌ batch requires --dir")
            sys.exit(1)
        if not Path(args.dir).is_dir():
            print(f"❌ ERROR: The directory '{args.dir}' does not exist on disk. Do not retry with this tool.")
            return results
        for f in sorted(Path(args.dir).glob(args.pattern)):
            if f.is_file():
                results.append((str(f), _safe_process(args, effective_action, str(f))))
        return results

    if args.path:
        results.append((args.path, _safe_process(args, effective_action, args.path)))
        return results

    if args.dir:
        if not Path(args.dir).is_dir():
            print(f"❌ ERROR: The directory '{args.dir}' does not exist on disk. Do not retry with this tool.")
            return results
        for f in sorted(Path(args.dir).glob(args.pattern)):
            if f.is_file():
                results.append((str(f), _safe_process(args, effective_action, str(f))))
        return results

    print("❌ --path or --dir required")
    sys.exit(1)


def _safe_process(args, effective_action: str, p: str) -> str:
    """Wrap process_file with I/O error guard — returns semantic error to LLM.

    Catches FileNotFoundError / OSError (permission, locked, etc.) and returns
    an explicit message so the agent FSM stays alive and can finalize cleanly.
    """
    p_str = str(p).strip("\"'")
    if not Path(p_str).exists():
        return f"❌ ERROR: The file path '{p_str}' does not exist on disk. Do not retry with this tool."
    try:
        return process_file(args, effective_action, p)
    except (FileNotFoundError, PermissionError, OSError) as exc:
        return f"❌ ERROR: Cannot read '{p_str}': {exc}. Do not retry with this tool."


def main() -> None:
    """file_analyst CLI entry point."""
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    adapt_mcp_schema()

    parser = build_parser()
    args = parser.parse_args()

    # Resolve any relative path against the bot root (not the skill CWD)
    bot_root = Path(__file__).resolve().parents[3]
    try:
        args = resolve_arg_paths(args, bot_root)
    except ValueError as exc:
        print(f"❌ ERROR: {exc} Do not retry with this tool.")
        return

    # Resolve effective action: batch delegates to --batch-action
    effective_action = args.batch_action if args.action == "batch" else args.action

    results = _collect_results(args, effective_action)

    # ── Semantic clustering for batch mode ──
    if args.action == "batch" and args.cluster:
        results = cluster_results(results, args.cluster_threshold)

    write_output(results, args.output)


if __name__ == "__main__":
    main()
