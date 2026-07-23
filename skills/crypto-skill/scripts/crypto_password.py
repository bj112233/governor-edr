"""crypto-skill password commands — password gen, uuid, phash, pverify.

Extracted from crypto.py (SRP).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import string
import uuid

import bcrypt

_PWD_ALGOS = {"argon2id", "bcrypt", "scrypt", "pbkdf2"}


def _emit(obj: dict | str, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(obj, ensure_ascii=False, indent=2))
        return
    if isinstance(obj, str):
        print(obj)
        return
    for k, v in obj.items():
        print(f"- **{k}**: `{v}`" if not isinstance(v, dict) else f"- **{k}**: {v}")


def cmd_password(args: argparse.Namespace) -> int:
    if args.length < 4 or args.length > 256:
        print("❌ --length must be 4..256")
        return 2
    if args.count < 1 or args.count > 100:
        print("❌ --count must be 1..100")
        return 2
    alphabet = string.ascii_letters + string.digits
    if args.symbols:
        alphabet += "!@#$%^&*()-_=+[]{};:,.<>?/"
    rng = secrets.SystemRandom()
    pwds = [
        "".join(rng.choice(alphabet) for _ in range(args.length))
        for _ in range(args.count)
    ]
    if args.format == "json":
        print(json.dumps({"length": args.length, "count": args.count, "passwords": pwds}, indent=2))
    else:
        for p in pwds:
            print(p)
    return 0


def cmd_uuid(args: argparse.Namespace) -> int:
    if args.count < 1 or args.count > 1000:
        print("❌ --count must be 1..1000")
        return 2
    out: list[str] = []
    for _ in range(args.count):
        if args.version == 1:
            out.append(str(uuid.uuid1()))
        elif args.version == 4:
            out.append(str(uuid.uuid4()))
        elif args.version == 3:
            if not args.namespace or not args.name:
                print("❌ uuid v3 requires --namespace and --name")
                return 2
            ns = getattr(uuid, f"NAMESPACE_{args.namespace.upper()}", None) or uuid.UUID(args.namespace)
            out.append(str(uuid.uuid3(ns, args.name)))
        elif args.version == 5:
            if not args.namespace or not args.name:
                print("❌ uuid v5 requires --namespace and --name")
                return 2
            ns = getattr(uuid, f"NAMESPACE_{args.namespace.upper()}", None) or uuid.UUID(args.namespace)
            out.append(str(uuid.uuid5(ns, args.name)))
        else:
            print(f"❌ Unsupported uuid version: {args.version}. Supported: 1, 3, 4, 5")
            return 2
    if args.format == "json":
        print(json.dumps({"version": args.version, "uuids": out}, indent=2))
    else:
        for u in out:
            print(u)
    return 0


def cmd_phash(args: argparse.Namespace) -> int:
    algo = args.algo.lower()
    if algo not in _PWD_ALGOS:
        print(f"❌ Unsupported algo: {algo}. Supported: {', '.join(sorted(_PWD_ALGOS))}")
        return 2
    text = args.text
    if text is None:
        print("❌ Provide --text")
        return 2
    pw = text.encode("utf-8")
    out: dict = {"algo": algo}
    if algo == "argon2id":
        try:
            import argon2
        except ImportError:
            print("❌ argon2-cffi not installed")
            return 2
        ph = argon2.PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32)
        out["hash"] = ph.hash(pw)
    elif algo == "bcrypt":
        rounds = args.rounds or 12
        salt = bcrypt.gensalt(rounds=rounds)
        h = bcrypt.hashpw(pw, salt).decode("ascii")
        out["hash"] = h
        out["rounds"] = rounds
    elif algo == "scrypt":
        salt = os.urandom(32)
        n = args.iterations or 2**14
        h_bytes = hashlib.scrypt(pw, salt=salt, n=n, r=8, p=1, dklen=32)
        out["hash"] = f"$scrypt$v=1$n={n},r=8,p=1${base64.b64encode(salt).decode()}${base64.b64encode(h_bytes).decode()}"
        out["salt"] = base64.b64encode(salt).decode()
        out["hex"] = h_bytes.hex()
    elif algo == "pbkdf2":
        salt = os.urandom(32)
        hash_name = args.hash_name or "sha256"
        iterations = args.iterations or 100000
        h_bytes = hashlib.pbkdf2_hmac(hash_name, pw, salt, iterations, dklen=32)
        out["hash"] = f"$pbkdf2-${hash_name}${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(h_bytes).decode()}"
        out["salt"] = base64.b64encode(salt).decode()
        out["hex"] = h_bytes.hex()
        out["iterations"] = iterations
        out["hash_name"] = hash_name
    _emit(out, args.format)
    return 0


def cmd_pverify(args: argparse.Namespace) -> int:
    text = args.text
    h = args.hash
    if text is None or h is None:
        print("❌ Provide --text and --hash")
        return 2
    pw = text.encode("utf-8")
    ok = False
    msg = ""
    if h.startswith("$argon2id$"):
        try:
            import argon2
        except ImportError:
            print("❌ argon2-cffi not installed")
            return 2
        ph = argon2.PasswordHasher()
        try:
            ph.verify(h, pw)
            ok = True
            msg = "Argon2id verification passed"
        except argon2.exceptions.VerifyMismatchError:
            msg = "Argon2id verification failed"
    elif h.startswith("$2b$") or h.startswith("$2a$") or h.startswith("$2y$"):
        ok = bcrypt.checkpw(pw, h.encode("ascii"))
        msg = "bcrypt verification passed" if ok else "bcrypt verification failed"
    elif h.startswith("$scrypt$"):
        msg = "scrypt verify not supported via string hash (use raw salt+hash)"
    elif h.startswith("$pbkdf2-"):
        msg = "pbkdf2 verify not supported via string hash (use raw salt+hash)"
    else:
        msg = "Unknown hash format"
    _emit({"valid": ok, "detail": msg}, args.format)
    return 0
