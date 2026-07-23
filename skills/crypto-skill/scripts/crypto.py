"""crypto-skill — offline cryptographic utilities.

Subcommands: hash | b64 | jwt | jwt-verify | password | uuid | hmac | phash | pverify | encrypt | decrypt | kdf

All operations are local; no network. CSPRNG via `secrets`.

Command implementations extracted to focused modules:
- crypto_hash.py:       hash, b64, hmac
- crypto_password.py:   password, uuid, phash, pverify
- crypto_jwt.py:        jwt, jwt-verify
- crypto_symmetric.py:  encrypt, decrypt, kdf
"""
from __future__ import annotations

import argparse
import sys

from crypto_hash import cmd_b64, cmd_hash, cmd_hmac
from crypto_jwt import cmd_jwt, cmd_jwt_verify
from crypto_password import cmd_password, cmd_phash, cmd_pverify, cmd_uuid
from crypto_symmetric import cmd_decrypt, cmd_encrypt, cmd_kdf


def main() -> int:
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception as exc:
            print(f"[WARN] stdout reconfigure failed: {exc}", file=sys.stderr)

    parser = argparse.ArgumentParser(prog="crypto.py")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def _add_fmt(p):
        p.add_argument("--format", choices=["text", "json"], default="text")

    p_hash = sub.add_parser("hash", help="Hash a string or file")
    p_hash.add_argument("--text")
    p_hash.add_argument("--file")
    p_hash.add_argument("--algo", default="sha256")
    _add_fmt(p_hash)
    p_hash.set_defaults(func=cmd_hash)

    p_b64 = sub.add_parser("b64", help="Base64 encode/decode")
    p_b64.add_argument("--encode", action="store_true")
    p_b64.add_argument("--decode", action="store_true")
    p_b64.add_argument("--urlsafe", action="store_true")
    p_b64.add_argument("--text")
    p_b64.add_argument("--file")
    _add_fmt(p_b64)
    p_b64.set_defaults(func=cmd_b64)

    p_jwt = sub.add_parser("jwt", help="Decode JWT (no verify)")
    p_jwt.add_argument("--token", required=True)
    _add_fmt(p_jwt)
    p_jwt.set_defaults(func=cmd_jwt)

    p_pwd = sub.add_parser("password", help="Generate strong passwords")
    p_pwd.add_argument("--length", type=int, default=20)
    p_pwd.add_argument("--count", type=int, default=1)
    p_pwd.add_argument("--symbols", action="store_true")
    _add_fmt(p_pwd)
    p_pwd.set_defaults(func=cmd_password)

    p_uuid = sub.add_parser("uuid", help="Generate UUIDs")
    p_uuid.add_argument("--count", type=int, default=1)
    p_uuid.add_argument("--version", type=int, default=4)
    p_uuid.add_argument("--namespace", help="DNS|URL|OID|X500 or a UUID for v3/v5")
    p_uuid.add_argument("--name", help="Name for v3/v5")
    _add_fmt(p_uuid)
    p_uuid.set_defaults(func=cmd_uuid)

    p_mac = sub.add_parser("hmac", help="Compute HMAC")
    p_mac.add_argument("--text")
    p_mac.add_argument("--file")
    p_mac.add_argument("--key", required=True)
    p_mac.add_argument("--algo", default="sha256")
    _add_fmt(p_mac)
    p_mac.set_defaults(func=cmd_hmac)

    p_phash = sub.add_parser("phash", help="Password hash (argon2id, bcrypt, scrypt, pbkdf2)")
    p_phash.add_argument("--text", required=True)
    p_phash.add_argument("--algo", default="argon2id")
    p_phash.add_argument("--rounds", type=int, help="bcrypt rounds")
    p_phash.add_argument("--iterations", type=int, help="scrypt/pbkdf2 iterations")
    p_phash.add_argument("--hash-name", default="sha256", help="pbkdf2 hash name")
    _add_fmt(p_phash)
    p_phash.set_defaults(func=cmd_phash)

    p_pverify = sub.add_parser("pverify", help="Verify password hash")
    p_pverify.add_argument("--text", required=True)
    p_pverify.add_argument("--hash", required=True)
    _add_fmt(p_pverify)
    p_pverify.set_defaults(func=cmd_pverify)

    p_jwtv = sub.add_parser("jwt-verify", help="Verify JWT signature")
    p_jwtv.add_argument("--token", required=True)
    p_jwtv.add_argument("--secret", help="HMAC secret")
    p_jwtv.add_argument("--pubkey", help="Public key file path")
    p_jwtv.add_argument("--algo", help="Allowed algorithms (comma-separated)")
    _add_fmt(p_jwtv)
    p_jwtv.set_defaults(func=cmd_jwt_verify)

    p_enc = sub.add_parser("encrypt", help="Encrypt text (fernet, aes-gcm, chacha20)")
    p_enc.add_argument("--text", required=True)
    p_enc.add_argument("--algo", default="fernet")
    p_enc.add_argument("--key", required=True)
    _add_fmt(p_enc)
    p_enc.set_defaults(func=cmd_encrypt)

    p_dec = sub.add_parser("decrypt", help="Decrypt text (fernet, aes-gcm, chacha20)")
    p_dec.add_argument("--text", required=True)
    p_dec.add_argument("--algo", default="fernet")
    p_dec.add_argument("--key", required=True)
    p_dec.add_argument("--nonce", help="Nonce for AES-GCM/ChaCha20 (base64)")
    _add_fmt(p_dec)
    p_dec.set_defaults(func=cmd_decrypt)

    p_kdf = sub.add_parser("kdf", help="Key derivation (pbkdf2, hkdf, scrypt)")
    p_kdf.add_argument("--password", required=True)
    p_kdf.add_argument("--algo", default="pbkdf2")
    p_kdf.add_argument("--salt", help="Base64 salt (generated if omitted)")
    p_kdf.add_argument("--length", type=int, default=32)
    p_kdf.add_argument("--iterations", type=int, help="pbkdf2/scrypt iterations")
    p_kdf.add_argument("--hash-name", default="sha256", help="pbkdf2 hash name")
    p_kdf.add_argument("--info", help="HKDF info string")
    _add_fmt(p_kdf)
    p_kdf.set_defaults(func=cmd_kdf)

    args = parser.parse_args()
    try:
        return args.func(args)
    except (FileNotFoundError, PermissionError, OSError) as exc:
        print(f"❌ ERROR: Crypto command failed: {exc}. Do not retry with this tool.")
        return 3
    except Exception as exc:
        import traceback

        traceback.print_exc(file=sys.stderr)
        print(f"❌ ERROR: Crypto command crashed unexpectedly: {exc}. Do not retry with this tool.")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
