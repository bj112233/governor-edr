"""crypto-skill hash commands — hash, b64, hmac.

Extracted from crypto.py (SRP).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac as _hmac
import json
from pathlib import Path

_HASH_ALGOS = {
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
    "sha3_256", "sha3_384", "sha3_512", "blake2b", "blake2s",
}


def _emit(obj: dict | str, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(obj, ensure_ascii=False, indent=2))
        return
    if isinstance(obj, str):
        print(obj)
        return
    for k, v in obj.items():
        print(f"- **{k}**: `{v}`" if not isinstance(v, dict) else f"- **{k}**: {v}")


def cmd_hash(args: argparse.Namespace) -> int:
    algo = args.algo.lower()
    if algo not in _HASH_ALGOS:
        print(f"❌ Unsupported algo: {algo}. Supported: {', '.join(sorted(_HASH_ALGOS))}")
        return 2
    h = hashlib.new(algo)
    if args.file:
        p = Path(args.file)
        if not p.is_file():
            print(f"❌ File not found: {p}")
            return 2
        try:
            with open(p, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
        except (PermissionError, OSError) as exc:
            print(f"❌ ERROR: Cannot read '{p}': {exc}. Do not retry with this tool.")
            return 3
        digest = h.hexdigest()
        out = {"algo": algo, "file": str(p), "size_bytes": p.stat().st_size, "hex": digest}
    elif args.text is not None:
        h.update(args.text.encode("utf-8"))
        digest = h.hexdigest()
        out = {"algo": algo, "input_len": len(args.text), "hex": digest}
    else:
        print("❌ Provide --text or --file")
        return 2
    _emit(out, args.format)
    return 0


def cmd_b64(args: argparse.Namespace) -> int:
    if args.encode == args.decode:
        print("❌ Choose exactly one of --encode / --decode")
        return 2
    text = args.text
    if text is None and args.file:
        try:
            text = Path(args.file).read_text(encoding="utf-8", errors="replace")
        except (FileNotFoundError, PermissionError, OSError) as exc:
            print(f"❌ ERROR: Cannot read '{args.file}': {exc}. Do not retry with this tool.")
            return 3
    if text is None:
        print("❌ Provide --text or --file")
        return 2
    enc = base64.urlsafe_b64encode if args.urlsafe else base64.b64encode
    dec = base64.urlsafe_b64decode if args.urlsafe else base64.b64decode
    try:
        if args.encode:
            result = enc(text.encode("utf-8")).decode("ascii")
        else:
            pad = "=" * (-len(text) % 4)
            result = dec(text + pad).decode("utf-8", errors="replace")
    except Exception as e:
        print(f"❌ b64 error: {e}")
        return 2
    _emit({"mode": "encode" if args.encode else "decode", "result": result}, args.format)
    return 0


def cmd_hmac(args: argparse.Namespace) -> int:
    algo = args.algo.lower()
    if algo not in _HASH_ALGOS:
        print(f"❌ Unsupported algo: {algo}")
        return 2
    if not args.key:
        print("❌ --key is required")
        return 2
    if args.text is None and not args.file:
        print("❌ Provide --text or --file")
        return 2
    key = args.key.encode("utf-8")
    mac = _hmac.new(key, digestmod=algo)
    if args.file:
        p = Path(args.file)
        if not p.is_file():
            print(f"❌ File not found: {p}")
            return 2
        try:
            with open(p, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    mac.update(chunk)
        except (PermissionError, OSError) as exc:
            print(f"❌ ERROR: Cannot read '{p}': {exc}. Do not retry with this tool.")
            return 3
    else:
        mac.update(args.text.encode("utf-8"))
    _emit({"algo": algo, "hex": mac.hexdigest()}, args.format)
    return 0
