"""Firewall skill state management — constants, audit, whitelist, utilities.

Extracted from firewall.py (SRP).
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

# ── Constants ──────────────────────────────────────────────────────────
_RULE_PREFIX = "SENTINEL_BLOCK_"
# Windows default firewall log path — overridable via env var for portability
# (Docker/Linux deployments can point this to /var/log/firewall.log etc.)
_FW_LOG = os.getenv(
    "SENTINEL_FW_LOG",
    r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log",
)
_IP_RE = re.compile(r"^[\d.]+$|^[\da-fA-F:]+$")
_NETSH_TIMEOUT = 10


def _state_dir() -> Path:
    base = os.getenv("SENTINEL_STATE_DIR")
    p = Path(base) if base else Path(__file__).resolve().parents[3] / "state"
    p = p / "skills" / "firewall"
    p.mkdir(parents=True, exist_ok=True)
    return p


_WHITELIST_FILE = _state_dir() / "whitelist.json"
_PENDING_FILE = _state_dir() / "pending_unblocks.json"
_AUDIT_FILE = _state_dir() / "audit.jsonl"


def _load_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def _save_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _audit(event: str, payload: dict) -> None:
    """Append-only JSONL audit log of every state-changing operation."""
    rec = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "event": event,
        **payload,
    }
    try:
        with open(_AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass


def _is_whitelisted(ip: str) -> bool:
    wl = _load_json(_WHITELIST_FILE, [])
    if ip in wl:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in wl:
        try:
            net = ipaddress.ip_network(entry, strict=False)
            if addr in net:
                return True
        except ValueError:
            continue
    return False


# ── OEM decode (Windows CMD pages cp850/cp862) ─────────────────────────
def _decode_oem(b: bytes) -> str:
    if not b:
        return ""
    for enc in ("cp862", "cp850", "utf-8"):
        try:
            return b.decode(enc)
        except UnicodeDecodeError:
            continue
    return b.decode("utf-8", errors="replace")


def _run(cmd: list[str], timeout: int = _NETSH_TIMEOUT) -> tuple[int, str, str]:
    """Run a command as list-args (no shell), return (returncode, stdout, stderr) — OEM-decoded."""
    try:
        result = subprocess.run(cmd, shell=False, capture_output=True, timeout=timeout)
        return (
            result.returncode,
            _decode_oem(result.stdout).strip(),
            _decode_oem(result.stderr).strip(),
        )
    except subprocess.TimeoutExpired:
        return (124, "", f"Timeout after {timeout}s")
    except Exception as e:  # pragma: no cover
        return (1, "", str(e))


def _parse_duration(s: str) -> int | None:
    """Parse '24h' / '90m' / '2d' / '300s' → seconds. Returns None if invalid."""
    if not s:
        return None
    m = re.match(r"^(\d+)\s*([smhd])$", s.strip().lower())
    if not m:
        return None
    n, unit = int(m.group(1)), m.group(2)
    return n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
