"""crypto-skill JWT commands — decode (no verify) + verify.

Extracted from crypto.py (SRP).
"""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path

import jwt

_JWT_HMAC_ALGS = {"HS256", "HS384", "HS512"}
_JWT_RSA_ALGS = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}
_JWT_EC_ALGS = {"ES256", "ES384", "ES512"}
_JWT_ALGS = _JWT_HMAC_ALGS | _JWT_RSA_ALGS | _JWT_EC_ALGS | {"EdDSA"}


def _emit(obj: dict | str, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(obj, ensure_ascii=False, indent=2))
        return
    if isinstance(obj, str):
        print(obj)
        return
    for k, v in obj.items():
        print(f"- **{k}**: `{v}`" if not isinstance(v, dict) else f"- **{k}**: {v}")


def cmd_jwt(args: argparse.Namespace) -> int:
    token = args.token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        print(f"❌ Invalid JWT — expected 3 parts, got {len(parts)}")
        return 2
    h_b64, p_b64, s_b64 = parts

    def _b64url_json(s: str) -> dict:
        pad = "=" * (-len(s) % 4)
        raw = base64.urlsafe_b64decode(s + pad).decode("utf-8", errors="replace")
        return json.loads(raw)

    try:
        header = _b64url_json(h_b64)
        payload = _b64url_json(p_b64)
    except Exception as e:
        print(f"❌ JWT decode failed: {e}")
        return 2
    _emit({
        "header": header,
        "payload": payload,
        "signature_present": bool(s_b64),
        "signature_bytes": len(s_b64),
        "warning": "Decoded only — signature NOT verified.",
    }, args.format)
    return 0


def cmd_jwt_verify(args: argparse.Namespace) -> int:
    token = args.token.strip()
    key = None
    if args.secret:
        key = args.secret
    elif args.pubkey:
        p = Path(args.pubkey)
        if not p.is_file():
            print(f"❌ Public key file not found: {p}")
            return 2
        key = p.read_text(encoding="utf-8")
    else:
        print("❌ Provide --secret or --pubkey")
        return 2
    algos = None
    if args.algo:
        algos = [a.strip().upper() for a in args.algo.split(",")]
    else:
        try:
            unverified_header = jwt.get_unverified_header(token)
            declared_algo = unverified_header.get("alg")
            if declared_algo:
                algos = [declared_algo]
        except Exception:
            pass
    try:
        payload = jwt.decode(token, key, algorithms=algos)
        header = jwt.get_unverified_header(token)
        out = {"valid": True, "header": header, "payload": payload, "signature_verified": True}
    except jwt.ExpiredSignatureError:
        out = {"valid": False, "error": "Token expired"}
    except jwt.InvalidTokenError as e:
        out = {"valid": False, "error": str(e)}
    _emit(out, args.format)
    return 0
