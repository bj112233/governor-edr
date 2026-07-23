"""Intel Skill — shared infrastructure utilities.

No business logic. Pure infrastructure: cache, embeddings, math, validation.
"""

from __future__ import annotations

import json
import os
import re
import time as _time
from pathlib import Path
from typing import Any

import requests

# ─────────────── Embeddings ───────────────

_LLM_API_BASE = os.getenv("LLM_API_BASE", "http://127.0.0.1:5001/v1")


def embed_texts(
    texts: list[str],
    model: str = os.getenv(
        "EMBEDDING_MODEL", "text-embedding-multilingual-e5-large-instruct"
    ),
) -> list[list[float]] | None:
    """Compute embeddings via local LLM endpoint. Returns None on failure."""
    try:
        url = f"{_LLM_API_BASE}/embeddings"
        prefixed = ["passage: " + t for t in texts]
        r = requests.post(
            url,
            json={"model": model, "input": prefixed},
            timeout=15,
            headers={"Content-Type": "application/json"},
        )
        r.raise_for_status()
        data = r.json()
        return [d["embedding"] for d in data.get("data", [])]
    except Exception:
        return None


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Pure-Python cosine similarity (-1..1)."""
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(x * x for x in b) ** 0.5
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


# ─────────────── Cache (TTL-based, disk JSON) ───────────────

_CACHE_BASE = Path(__file__).resolve().parents[3] / "state"


def _cache_dir() -> Path:
    """Resolve cache dir lazily from SENTINEL_STATE_DIR.

    Module-level binding would freeze the env at import time, breaking
    runtime redirection (and test isolation via monkeypatch.setenv).
    """
    base = Path(os.getenv("SENTINEL_STATE_DIR") or _CACHE_BASE)
    d = base / "skills" / "intel_cache"
    d.mkdir(parents=True, exist_ok=True)
    return d

_TTL_BY_SOURCE = {
    "abuseipdb": 3600,       # 1h
    "virustotal": 86400,     # 24h (heaviest quota — maximize cache hit)
    "maltiverse_ip": 21600,  # 6h
    "maltiverse_hash": 21600,# 6h
    "rdap": 604800,          # 7d
    "ipapi_co": 21600,       # 6h
    "shodan": 21600,         # 6h
    "cert_il": 3600,         # 1h
    "il_domain": 21600,      # 6h
}


def cache_get(source: str, key: str) -> dict[str, Any] | None:
    """Return cached entry if fresh, else None."""
    safe_key = re.sub(r"[^a-zA-Z0-9._-]", "_", key)[:128]
    fpath = _cache_dir() / f"{source}_{safe_key}.json"
    if not fpath.exists():
        return None
    try:
        data = json.loads(fpath.read_text(encoding="utf-8"))
        ttl = _TTL_BY_SOURCE.get(source, 3600)
        if _time.time() - float(data.get("_ts", 0)) > ttl:
            return None
        return data.get("value")
    except Exception:
        return None


def cache_set(source: str, key: str, value: dict[str, Any]) -> None:
    """Persist a cache entry. Silently ignores I/O errors."""
    safe_key = re.sub(r"[^a-zA-Z0-9._-]", "_", key)[:128]
    fpath = _cache_dir() / f"{source}_{safe_key}.json"
    try:
        fpath.write_text(
            json.dumps({"_ts": _time.time(), "value": value}, ensure_ascii=False),
            encoding="utf-8",
        )
    except Exception:
        pass


# ─────────────── Validation helpers ───────────────

import ipaddress


def is_private_ip(ip: str) -> bool:
    """Return True if IP is loopback, link-local, multicast, or RFC1918."""
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_private
            or addr.is_reserved
        )
    except ValueError:
        return True  # Invalid IP treated as private/skip


_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32,64}$")


def looks_like_ip(target: str) -> bool:
    return bool(_IPV4_RE.match(target) or _IPV6_RE.match(target))


def looks_like_domain(target: str) -> bool:
    return bool(_DOMAIN_RE.match(target))


def looks_like_hash(target: str) -> bool:
    return bool(_HASH_RE.match(target))
