---
name: crypto-skill
description: "Cryptographic utilities — hashing, base64, JWT decode/verify, password hashing (argon2id/bcrypt/scrypt/pbkdf2), encryption (Fernet/AES-GCM/ChaCha20), key derivation (PBKDF2/HKDF/scrypt), password generation, UUIDs, HMAC. NOT for cryptocurrency prices — use stocks-skill with crypto command for Bitcoin/Ethereum. Subcommands: hash / b64 / jwt / jwt-verify / password / uuid / hmac / phash / pverify / encrypt / decrypt / kdf. Trigger when user asks hash, sha256, md5, base64, JWT, decode token, verify JWT, encrypt, decrypt, generate password, סיסמה אקראית, uuid, hmac, argon2, bcrypt, PBKDF2, KDF, או מבקש קידוד/פענוח של מחרוזת. Uses stdlib + cryptography + PyJWT + argon2-cffi + bcrypt. No network, no API keys."
metadata: {"clawdbot":{"emoji":"🔐","commands":["hash","b64","jwt","jwt-verify","password","uuid","hmac","phash","pverify","encrypt","decrypt","kdf"],"arg_template":"scripts/crypto.py {command} {args}","requires":{"bins":["python"],"python_libs":["cryptography","PyJWT","argon2-cffi","bcrypt"]},"install":[],"commands_schema":{"hash":{"properties":{"text":{"type":"string"},"file":{"type":"string"},"algo":{"type":"string","default":"sha256"},"format":{"type":"string","enum":["text","json"],"default":"text"}}},"b64":{"properties":{"encode":{"type":"boolean"},"decode":{"type":"boolean"},"urlsafe":{"type":"boolean"},"text":{"type":"string"},"file":{"type":"string"},"format":{"type":"string","enum":["text","json"],"default":"text"}}},"jwt":{"properties":{"token":{"type":"string"},"format":{"type":"string","enum":["text","json"],"default":"text"}},"required":["token"]},"jwt-verify":{"properties":{"token":{"type":"string"},"secret":{"type":"string"},"pubkey":{"type":"string"},"algo":{"type":"string"},"format":{"type":"string","enum":["text","json"],"default":"text"}},"required":["token"]},"password":{"properties":{"length":{"type":"integer","default":20},"count":{"type":"integer","default":1},"symbols":{"type":"boolean"},"format":{"type":"string","enum":["text","json"],"default":"text"}}},"uuid":{"properties":{"count":{"type":"integer","default":1},"version":{"type":"integer","default":4},"namespace":{"type":"string"},"name":{"type":"string"},"format":{"type":"string","enum":["text","json"],"default":"text"}}},"hmac":{"properties":{"text":{"type":"string"},"file":{"type":"string"},"key":{"type":"string"},"algo":{"type":"string","default":"sha256"},"format":{"type":"string","enum":["text","json"],"default":"text"}},"required":["key"]},"phash":{"properties":{"text":{"type":"string"},"algo":{"type":"string","default":"argon2id"},"rounds":{"type":"integer"},"iterations":{"type":"integer"},"hash-name":{"type":"string","default":"sha256"},"format":{"type":"string","enum":["text","json"],"default":"text"}},"required":["text"]},"pverify":{"properties":{"text":{"type":"string"},"hash":{"type":"string"},"format":{"type":"string","enum":["text","json"],"default":"text"}},"required":["text","hash"]},"encrypt":{"properties":{"text":{"type":"string"},"algo":{"type":"string","default":"fernet"},"key":{"type":"string"},"format":{"type":"string","enum":["text","json"],"default":"text"}},"required":["text","key"]},"decrypt":{"properties":{"text":{"type":"string"},"algo":{"type":"string","default":"fernet"},"key":{"type":"string"},"nonce":{"type":"string"},"format":{"type":"string","enum":["text","json"],"default":"text"}},"required":["text","key"]},"kdf":{"properties":{"password":{"type":"string"},"algo":{"type":"string","default":"pbkdf2"},"salt":{"type":"string"},"length":{"type":"integer","default":32},"iterations":{"type":"integer"},"hash-name":{"type":"string","default":"sha256"},"info":{"type":"string"},"format":{"type":"string","enum":["text","json"],"default":"text"}},"required":["password"]}}}}
---

# Crypto Skill

כלי קריפטוגרפיה אופליין — hashing, base64, JWT decode/verify, password hashing, encryption, key derivation, UUIDs, HMAC. מקומי לחלוטין — אין רשת, אין API.

## Quick start

```bash
# Hash של מחרוזת
python {baseDir}/scripts/crypto.py hash --text "hello" --algo sha256

# Hash של קובץ
python {baseDir}/scripts/crypto.py hash --file C:/path/to/file.bin --algo sha256

# Base64 encode/decode
python {baseDir}/scripts/crypto.py b64 --encode --text "hello world"
python {baseDir}/scripts/crypto.py b64 --decode --text "aGVsbG8gd29ybGQ="

# JWT decode (ללא verify)
python {baseDir}/scripts/crypto.py jwt --token "eyJhbGc..."

# JWT verify עם secret
python {baseDir}/scripts/crypto.py jwt-verify --token "eyJhbGc..." --secret "mysecret"

# Password hashing — Argon2id (OWASP 2026 baseline)
python {baseDir}/scripts/crypto.py phash --text "mypassword" --algo argon2id

# Password verify
python {baseDir}/scripts/crypto.py pverify --text "mypassword" --hash "$argon2id$..."

# הצפנה — Fernet
python {baseDir}/scripts/crypto.py encrypt --text "secret message" --algo fernet --key "base64key..."

# פענוח
python {baseDir}/scripts/crypto.py decrypt --text "ciphertext..." --algo fernet --key "base64key..."

# Key derivation — PBKDF2
python {baseDir}/scripts/crypto.py kdf --password "secret" --algo pbkdf2 --length 32

# יצירת סיסמאות
python {baseDir}/scripts/crypto.py password --length 20 --count 5 --symbols

# UUIDs
python {baseDir}/scripts/crypto.py uuid --count 5 --version 4

# HMAC
python {baseDir}/scripts/crypto.py hmac --text "data" --key "secret" --algo sha256
```

## פקודות

| Command | תיאור |
|---------|--------|
| `hash` | חישוב hash (md5/sha1/sha256/sha512/sha3_256/blake2b) למחרוזת או קובץ |
| `b64` | קידוד/פענוח base64 (גם urlsafe) |
| `jwt` | פענוח JWT — מציג header + payload + signature info (ללא verify) |
| `jwt-verify` | אימות JWT signature עם secret / public key |
| `phash` | Password hashing — Argon2id, bcrypt, scrypt, PBKDF2 |
| `pverify` | אימות password hash |
| `encrypt` | הצפנה — Fernet, AES-GCM, ChaCha20-Poly1305 |
| `decrypt` | פענוח |
| `kdf` | גזירת מפתח — PBKDF2, HKDF, scrypt |
| `password` | סיסמאות אקראיות חזקות מבוססות `secrets` |
| `uuid` | UUID v1/v3/v4/v5/v7 |
| `hmac` | HMAC עם key + algo |

## אלגוריתמים נתמכים

- **Hash:** md5, sha1, sha256, sha384, sha512, sha3_256, sha3_512, blake2b, blake2s
- **HMAC:** כל ה-hashes לעיל
- **Password Hashing:** argon2id (OWASP 2026), bcrypt, scrypt, pbkdf2
- **Encryption:** fernet (AES-128-CBC + HMAC), aes-gcm (AES-256-GCM), chacha20 (ChaCha20-Poly1305)
- **Key Derivation:** pbkdf2, hkdf, scrypt

## אבטחה

- כל החישובים מקומיים — ‎אין שליחת נתונים לרשת.
- יצירת סיסמאות משתמשת ב-`secrets.SystemRandom` (CSPRNG).
- Password hashing ברירת מחדל: **Argon2id** (memory-hard, OWASP 2026 baseline).
- הצפנה AES-GCM ו-ChaCha20-Poly1305 כוללות אימות תקינות (AEAD).
- JWT verify תומך ב-HMAC (HS256/384/512), RSA (RS/PS256/384/512), EC (ES256/384/512) ו-EdDSA.
