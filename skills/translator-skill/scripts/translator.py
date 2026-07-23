"""Multi-backend translator with fallback chain: MyMemory → LibreTranslate.

All backends are free, require no API key, and auto-detect source language.

Shim/facade layer for backward compatibility. All logic has been moved to the
new modular architecture (SRP, ≤300 lines per file):

  translator_config.py       — constants, language utils, langdetect bootstrap
  translator_backends.py     — TranslationBackend ABC + 3 concrete backends
  translator_orchestrator.py — MultiBackendTranslator (fallback, circuit breaker, detect)
  translator.py              — this facade: re-exports + CLI entry point
"""

from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# ── Re-export public API from focused modules ──
from translator_config import (
    CHUNK_SIZE,
    LANG_ALIASES,
    LANGDETECT_AVAILABLE,
    LIBRE_INSTANCES,
    MAX_CHUNK_RETRIES,
    MAX_WORKERS,
    _chunker,
    _normalize_lang,
    chunk_text,
)
from translator_backends import (
    LibreTranslateBackend,
    MyMemoryBackend,
    TranslationBackend,
)
from translator_orchestrator import MultiBackendTranslator, translator

__all__ = [
    # Config / constants
    "CHUNK_SIZE",
    "MAX_CHUNK_RETRIES",
    "MAX_WORKERS",
    "LIBRE_INSTANCES",
    "LANG_ALIASES",
    "LANGDETECT_AVAILABLE",
    "_chunker",
    "_normalize_lang",
    "chunk_text",
    # Backends
    "TranslationBackend",
    "LibreTranslateBackend",
    "MyMemoryBackend",
    # Orchestrator
    "MultiBackendTranslator",
    "translator",
    # CLI
    "main",
]


def _run_bulk(args: argparse.Namespace) -> None:
    """Translate every text file under --bulk-dir in parallel."""
    if not args.target:
        print("❌ --bulk-dir requires --to")
        sys.exit(1)
    src = Path(args.bulk_dir)
    if not src.is_dir():
        print(f"❌ Directory not found: {src}")
        sys.exit(1)
    out_dir = Path(args.output) if args.output else src / "translated"
    out_dir.mkdir(parents=True, exist_ok=True)
    translated_count = 0
    failed = []
    files = [f for f in sorted(src.glob(args.bulk_pattern)) if f.is_file()]
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(
                translator.translate,
                f.read_text(encoding="utf-8", errors="replace"),
                args.source,
                args.target,
                args.backend,
            ): f
            for f in files
        }
        for fut in as_completed(futures):
            f = futures[fut]
            try:
                result, backend_name = fut.result()
                (out_dir / f.name).write_text(result, encoding="utf-8")
                translated_count += 1
                print(f"✅ {f.name} ({backend_name})")
            except Exception as e:
                failed.append(f"{f.name}: {e}")
    msg = f"✅ תורגמו {translated_count}/{len(files)} קבצים → {out_dir}"
    if failed:
        msg += f"\n⚠️ נכשלו {len(failed)}:\n" + "\n".join(f"  - {x}" for x in failed)
    print(msg)


def _run_single(args: argparse.Namespace, text: str) -> None:
    """Detect-only or single-text translation + output."""
    if args.detect:
        info = translator.detect_language(text)
        print(json.dumps(info, ensure_ascii=False, indent=2))
        return

    if not args.target:
        print("❌ --to is required (or use --detect)")
        sys.exit(1)

    try:
        result, backend_name = translator.translate(
            text, args.source, args.target, force_backend=args.backend
        )
    except Exception as e:
        print(f"❌ Translation error: {e}")
        sys.exit(2)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(result)
        except (FileNotFoundError, PermissionError, OSError) as exc:
            print(f"❌ ERROR: Cannot write to '{args.output}': {exc}. Do not retry with this tool.")
            sys.exit(3)
        print(f"✅ Saved {len(result)} chars to {args.output} (via {backend_name})")
    else:
        print(result)
        if args.backend:
            print(f"(via {backend_name})", file=sys.stderr)


def main() -> None:
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(
        description="Multi-backend translator (MyMemory → LibreTranslate)"
    )
    parser.add_argument("--text", help="Text to translate")
    parser.add_argument("--file", help="Read text from file")
    parser.add_argument("--stdin", action="store_true")
    parser.add_argument(
        "--from",
        dest="source",
        default="auto",
        help="Source language (default: auto-detect)",
    )
    parser.add_argument(
        "--to",
        dest="target",
        help="Target language code (he, en, ar, fr, ...). Required unless --detect.",
    )
    parser.add_argument(
        "--detect",
        action="store_true",
        help="Only detect source language (no translation)",
    )
    parser.add_argument(
        "--backend",
        choices=["libretranslate", "mymemory"],
        help="Force a specific backend",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=MAX_WORKERS,
        help="Max parallel workers for chunk translation (default: 3)",
    )
    parser.add_argument(
        "--bulk-dir",
        dest="bulk_dir",
        help="Translate every text file under this directory; output to --output dir.",
    )
    parser.add_argument(
        "--bulk-pattern",
        dest="bulk_pattern",
        default="*.txt",
        help="Glob pattern for --bulk-dir (default: *.txt)",
    )
    parser.add_argument(
        "--output", help="Save translated text to file (or directory for --bulk-dir)"
    )
    args = parser.parse_args()

    if args.bulk_dir:
        _run_bulk(args)
        return

    if args.text:
        text = args.text
    elif args.file:
        try:
            with open(args.file, encoding="utf-8") as f:
                text = f.read()
        except (FileNotFoundError, PermissionError, OSError) as exc:
            print(f"❌ ERROR: Cannot read '{args.file}': {exc}. Do not retry with this tool.")
            sys.exit(3)
    elif args.stdin:
        text = sys.stdin.read()
    else:
        print("❌ Provide --text, --file, --stdin, or --bulk-dir")
        sys.exit(1)

    _run_single(args, text)


if __name__ == "__main__":
    main()
