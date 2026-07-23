"""crypto-skill symmetric crypto — encrypt, decrypt, kdf.

Extracted from crypto.py (SRP).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_ENC_ALGOS = {"fernet", "aes-gcm", "chacha20"}
_KDF_ALGOS = {"pbkdf2", "hkdf", "scrypt"}


def _emit(obj: dict | str, fmt: str) -> None:
    import json
    if fmt == "json":
        print(json.dumps(obj, ensure_ascii=False, indent=2))
        return
    if isinstance(obj, str):
        print(obj)
        return
    for k, v in obj.items():
        print(f"- **{k}**: `{v}`" if not isinstance(v, dict) else f"- **{k}**: {v}")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text)


def cmd_encrypt(args: argparse.Namespace) -> int:
    algo = args.algo.lower()
    if algo not in _ENC_ALGOS:
        print(f"❌ Unsupported algo: {algo}. Supported: {', '.join(sorted(_ENC_ALGOS))}")
        return 2
    text = args.text
    if text is None:
        print("❌ Provide --text")
        return 2
    data = text.encode("utf-8")
    key_input = args.key
    if not key_input:
        print("❌ Provide --key")
        return 2
    out: dict = {"algo": algo}
    if algo == "fernet":
        try:
            f = Fernet(key_input)
            ct = f.encrypt(data)
            out["ciphertext"] = ct.decode("ascii")
        except ValueError as e:
            print(f"❌ Fernet key error: {e}")
            return 2
    elif algo == "aes-gcm":
        try:
            key = _b64d(key_input)
            if len(key) not in (16, 24, 32):
                print("❌ AES-GCM key must be 16, 24, or 32 bytes (base64)")
                return 2
            nonce = os.urandom(12)
            aesgcm = AESGCM(key)
            ct = aesgcm.encrypt(nonce, data, None)
            out["ciphertext"] = _b64(ct)
            out["nonce"] = _b64(nonce)
            out["key_length"] = len(key)
        except Exception as e:
            print(f"❌ AES-GCM error: {e}")
            return 2
    elif algo == "chacha20":
        try:
            key = _b64d(key_input)
            if len(key) != 32:
                print("❌ ChaCha20 key must be 32 bytes (base64)")
                return 2
            nonce = os.urandom(12)
            chacha = ChaCha20Poly1305(key)
            ct = chacha.encrypt(nonce, data, None)
            out["ciphertext"] = _b64(ct)
            out["nonce"] = _b64(nonce)
        except Exception as e:
            print(f"❌ ChaCha20 error: {e}")
            return 2
    _emit(out, args.format)
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    algo = args.algo.lower()
    if algo not in _ENC_ALGOS:
        print(f"❌ Unsupported algo: {algo}. Supported: {', '.join(sorted(_ENC_ALGOS))}")
        return 2
    text = args.text
    if text is None:
        print("❌ Provide --text")
        return 2
    key_input = args.key
    if not key_input:
        print("❌ Provide --key")
        return 2
    out: dict = {"algo": algo}
    if algo == "fernet":
        try:
            f = Fernet(key_input)
            pt = f.decrypt(text.encode("ascii"))
            out["plaintext"] = pt.decode("utf-8", errors="replace")
        except InvalidToken:
            print("❌ Fernet decryption failed: invalid token")
            return 2
        except ValueError as e:
            print(f"❌ Fernet key error: {e}")
            return 2
    elif algo == "aes-gcm":
        try:
            key = _b64d(key_input)
            if len(key) not in (16, 24, 32):
                print("❌ AES-GCM key must be 16, 24, or 32 bytes (base64)")
                return 2
            nonce = _b64d(args.nonce) if args.nonce else os.urandom(12)
            ct = _b64d(text)
            aesgcm = AESGCM(key)
            pt = aesgcm.decrypt(nonce, ct, None)
            out["plaintext"] = pt.decode("utf-8", errors="replace")
            out["nonce"] = _b64(nonce)
        except Exception as e:
            print(f"❌ AES-GCM decryption error: {e}")
            return 2
    elif algo == "chacha20":
        try:
            key = _b64d(key_input)
            if len(key) != 32:
                print("❌ ChaCha20 key must be 32 bytes (base64)")
                return 2
            nonce = _b64d(args.nonce) if args.nonce else os.urandom(12)
            ct = _b64d(text)
            chacha = ChaCha20Poly1305(key)
            pt = chacha.decrypt(nonce, ct, None)
            out["plaintext"] = pt.decode("utf-8", errors="replace")
            out["nonce"] = _b64(nonce)
        except Exception as e:
            print(f"❌ ChaCha20 decryption error: {e}")
            return 2
    _emit(out, args.format)
    return 0


def cmd_kdf(args: argparse.Namespace) -> int:
    algo = args.algo.lower()
    if algo not in _KDF_ALGOS:
        print(f"❌ Unsupported algo: {algo}. Supported: {', '.join(sorted(_KDF_ALGOS))}")
        return 2
    password = args.password
    if password is None:
        print("❌ Provide --password")
        return 2
    pw = password.encode("utf-8")
    length = args.length or 32
    salt_input = args.salt
    out: dict = {"algo": algo, "length": length}
    if algo == "pbkdf2":
        salt = _b64d(salt_input) if salt_input else os.urandom(32)
        hash_name = args.hash_name or "sha256"
        iterations = args.iterations or 100000
        dk = hashlib.pbkdf2_hmac(hash_name, pw, salt, iterations, dklen=length)
        out["key"] = _b64(dk)
        out["salt"] = _b64(salt)
        out["iterations"] = iterations
        out["hash_name"] = hash_name
    elif algo == "hkdf":
        salt = _b64d(salt_input) if salt_input else os.urandom(32)
        info = args.info.encode("utf-8") if args.info else b""
        hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
        dk = hkdf.derive(pw)
        out["key"] = _b64(dk)
        out["salt"] = _b64(salt)
    elif algo == "scrypt":
        salt = _b64d(salt_input) if salt_input else os.urandom(32)
        n = args.iterations or 2**14
        dk = hashlib.scrypt(pw, salt=salt, n=n, r=8, p=1, dklen=length)
        out["key"] = _b64(dk)
        out["salt"] = _b64(salt)
        out["n"] = n
        out["r"] = 8
        out["p"] = 1
    _emit(out, args.format)
    return 0
