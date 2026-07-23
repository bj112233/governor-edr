"""Firewall skill subcommands — block, unblock, block-cidr, whitelist, sweep, audit, list, drops, stats.

Extracted from firewall.py (SRP).
"""
from __future__ import annotations

import ipaddress
import json
import os
from datetime import datetime, timedelta, timezone

from firewall_backends import FirewallBackend, _get_backend
from firewall_list import cmd_list  # noqa: F401 — re-exported
from firewall_state import (
    _AUDIT_FILE,
    _IP_RE,
    _PENDING_FILE,
    _RULE_PREFIX,
    _WHITELIST_FILE,
    _audit,
    _is_whitelisted,
    _load_json,
    _parse_duration,
    _save_json,
)


def cmd_block(
    backend: FirewallBackend, ip: str, duration: str | None = None, reason: str = ""
) -> str:
    if not _IP_RE.match(ip.strip()):
        return f"❌ כתובת IP לא תקינה: {ip}"
    ip = ip.strip()
    if _is_whitelisted(ip):
        _audit("block_blocked_by_whitelist", {"ip": ip, "reason": reason})
        return f"🛡️ IP {ip} נמצא ב-whitelist — חסימה נמנעה."
    safe = ip.replace(":", "_").replace("/", "_")
    rule_out = f"{_RULE_PREFIX}{safe}"
    rule_in = f"{_RULE_PREFIX}IN_{safe}"
    failures = []
    rc, _, err = backend.add_rule(rule_out, "out", "block", ip)
    if rc != 0:
        failures.append(f"out: rc={rc} {err[:120]}")
    rc, _, err = backend.add_rule(rule_in, "in", "block", ip)
    if rc != 0:
        failures.append(f"in: rc={rc} {err[:120]}")
    expires_at: str | None = None
    if duration:
        secs = _parse_duration(duration)
        if secs is None:
            return f"❌ duration לא תקין: {duration} (use 30s / 15m / 24h / 7d)"
        expires_dt = datetime.now(timezone.utc) + timedelta(seconds=secs)
        expires_at = expires_dt.isoformat(timespec="seconds")
        pending = _load_json(_PENDING_FILE, {})
        pending[ip] = {
            "expires_at": expires_at,
            "reason": reason,
            "backend": backend.name,
        }
        _save_json(_PENDING_FILE, pending)
    _audit(
        "block",
        {"ip": ip, "reason": reason, "expires_at": expires_at, "failures": failures},
    )
    if failures:
        return f"⚠️ חסימת {ip} הצליחה חלקית — {'; '.join(failures)}"
    suffix = f" (auto-unblock ב-{expires_at})" if expires_at else ""
    return f"✅ IP {ip} נחסם (inbound + outbound) בחומת האש.{suffix}"


def cmd_unblock(backend: FirewallBackend, ip: str, source: str = "manual") -> str:
    if not _IP_RE.match(ip.strip()):
        return f"❌ כתובת IP לא תקינה: {ip}"
    ip = ip.strip()
    safe = ip.replace(":", "_").replace("/", "_")
    rule_out = f"{_RULE_PREFIX}{safe}"
    rule_in = f"{_RULE_PREFIX}IN_{safe}"
    deleted = []
    for rule_name in (rule_out, rule_in):
        rc, out, err = backend.delete_rule(rule_name)
        if "No rules match" not in out and rc == 0:
            deleted.append(rule_name)
    pending = _load_json(_PENDING_FILE, {})
    if pending.pop(ip, None) is not None:
        _save_json(_PENDING_FILE, pending)
    matched = bool(deleted)
    _audit("unblock", {"ip": ip, "matched": matched, "source": source})
    if not matched:
        return f"⚠️ לא נמצאו חוקי חסימה עבור IP {ip} (ייתכן שלא היה חסום)."
    return f"✅ IP {ip} שוחרר מחומת האש."


def cmd_block_cidr(backend: FirewallBackend, network: str, reason: str = "") -> str:
    """Block an entire CIDR range with a single firewall rule (remoteip=cidr)."""
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError as e:
        return f"❌ CIDR לא תקין: {e}"
    cidr = str(net)
    safe = cidr.replace(":", "_").replace("/", "_")
    rule_out = f"{_RULE_PREFIX}{safe}"
    rule_in = f"{_RULE_PREFIX}IN_{safe}"
    failures = []
    rc, _, err = backend.add_rule(rule_out, "out", "block", cidr)
    if rc != 0:
        failures.append(f"out: rc={rc} {err[:120]}")
    rc, _, err = backend.add_rule(rule_in, "in", "block", cidr)
    if rc != 0:
        failures.append(f"in: rc={rc} {err[:120]}")
    _audit("block_cidr", {"cidr": cidr, "reason": reason, "failures": failures})
    if failures:
        return f"⚠️ חסימת {cidr} הצליחה חלקית — {'; '.join(failures)}"
    return f"✅ רשת {cidr} נחסמה (inbound + outbound)."


def cmd_block_port(backend: FirewallBackend, port: int, protocol: str = "TCP", reason: str = "") -> str:
    """Block inbound + outbound traffic on a specific port."""
    if not (1 <= port <= 65535):
        return f"❌ פורט לא תקין: {port} (טווח תקין: 1-65535)"
    proto = protocol.upper()
    if proto not in ("TCP", "UDP"):
        return f"❌ פרוטוקול לא תקין: {protocol} (תקין: TCP או UDP)"
    safe = f"PORT_{proto}_{port}"
    rule_out = f"{_RULE_PREFIX}{safe}"
    rule_in = f"{_RULE_PREFIX}IN_{safe}"
    failures = []
    rc, _, err = backend.add_rule(rule_out, "out", "block", "", localport=str(port), protocol=proto)
    if rc != 0:
        failures.append(f"out: rc={rc} {err[:120]}")
    rc, _, err = backend.add_rule(rule_in, "in", "block", "", localport=str(port), protocol=proto)
    if rc != 0:
        failures.append(f"in: rc={rc} {err[:120]}")
    _audit("block_port", {"port": port, "protocol": proto, "reason": reason, "failures": failures})
    if failures:
        return f"⚠️ חסימת פורט {port}/{proto} הצליחה חלקית — {'; '.join(failures)}"
    return f"✅ פורט {port}/{proto} נחסם (inbound + outbound)."


def cmd_unblock_port(backend: FirewallBackend, port: int, protocol: str = "TCP") -> str:
    """Remove port block rules."""
    proto = protocol.upper()
    if proto not in ("TCP", "UDP"):
        return f"❌ פרוטוקול לא תקין: {protocol}"
    safe = f"PORT_{proto}_{port}"
    rule_out = f"{_RULE_PREFIX}{safe}"
    rule_in = f"{_RULE_PREFIX}IN_{safe}"
    deleted = []
    for rule_name in (rule_out, rule_in):
        rc, out, err = backend.delete_rule(rule_name)
        if "No rules match" not in out and rc == 0:
            deleted.append(rule_name)
    _audit("unblock_port", {"port": port, "protocol": proto, "matched": bool(deleted)})
    if not deleted:
        return f"⚠️ לא נמצאו חוקי חסימה עבור פורט {port}/{proto}."
    return f"✅ פורט {port}/{proto} שוחרר מחומת האש."


def cmd_whitelist(action: str, ip: str | None) -> str:
    wl = _load_json(_WHITELIST_FILE, [])
    if action == "list":
        if not wl:
            return "📋 Whitelist ריק."
        return "# 🛡️ Whitelist\n\n" + "\n".join(f"- `{e}`" for e in sorted(wl))
    if action in ("add", "remove"):
        if not ip:
            return "❌ דורש --ip"
        target = ip.strip()
        try:
            ipaddress.ip_network(target, strict=False)
        except ValueError as e:
            return f"❌ ערך לא תקין: {e}"
        wl_set = set(wl)
        if action == "add":
            if target in wl_set:
                return f"ℹ️  `{target}` כבר ב-whitelist."
            wl_set.add(target)
            _save_json(_WHITELIST_FILE, sorted(wl_set))
            _audit("whitelist_add", {"target": target})
            return f"✅ `{target}` נוסף ל-whitelist (חסימות אוטומטיות עליו ייחסמו)."
        wl_set.discard(target)
        _save_json(_WHITELIST_FILE, sorted(wl_set))
        _audit("whitelist_remove", {"target": target})
        return f"✅ `{target}` הוסר מ-whitelist."


def cmd_sweep(backend: FirewallBackend | None = None) -> str:
    """Auto-unblock all pending IPs whose duration has expired."""
    pending = _load_json(_PENDING_FILE, {})
    if not pending:
        return "📭 אין חסימות-עם-תפוגה ממתינות."
    now = datetime.now(timezone.utc)
    released = []
    kept = {}
    for ip, info in pending.items():
        try:
            exp = datetime.fromisoformat(
                info.get("expires_at", "").replace("Z", "+00:00")
            )
        except (TypeError, ValueError):
            kept[ip] = info
            continue
        if exp <= now:
            rule_backend = _get_backend(info.get("backend", "netsh"))
            cmd_unblock(rule_backend, ip, source="sweep")
            released.append(ip)
        else:
            kept[ip] = info
    _save_json(_PENDING_FILE, kept)
    if not released:
        return f"⏳ {len(kept)} חסימות זמניות עדיין פעילות."
    return f"✅ שוחררו {len(released)} IPs: {', '.join(released)}"


def cmd_audit(count: int = 20) -> str:
    if not _AUDIT_FILE.is_file():
        return "📭 אין רישומי audit."
    try:
        with open(_AUDIT_FILE, encoding="utf-8") as f:
            lines = f.readlines()
    except OSError as e:
        return f"❌ שגיאה: {e}"
    recent = lines[-count:]
    out = [f"# 📜 Firewall Audit — {len(recent)} רישומים אחרונים\n"]
    for raw in recent:
        try:
            rec = json.loads(raw)
            ts = rec.get("ts", "?")
            ev = rec.get("event", "?")
            target = rec.get("ip") or rec.get("cidr") or rec.get("target") or ""
            extra = []
            if rec.get("expires_at"):
                extra.append(f"expires={rec['expires_at']}")
            if rec.get("source"):
                extra.append(f"src={rec['source']}")
            if rec.get("reason"):
                extra.append(f'reason="{rec["reason"]}"')
            extra_str = f"  ({', '.join(extra)})" if extra else ""
            out.append(f"- `{ts}` **{ev}** `{target}`{extra_str}")
        except json.JSONDecodeError:
            continue
    return "\n".join(out)


def _read_log_tail(path: str, max_lines: int = 200) -> tuple[str | None, str]:
    if not os.path.exists(path):
        return (
            None,
            "Firewall log not found.\nEnable via: netsh advfirewall set "
            "allprofiles logging droppedconnections enable",
        )
    try:
        with open(path, "r", errors="replace") as f:
            all_lines = f.readlines()
    except PermissionError:
        return (None, "Permission denied. Run as Administrator.")
    except Exception as e:
        return (None, f"[ERROR] {e}")
    data = [ln.rstrip() for ln in all_lines if not ln.startswith("#")]
    return ("\n".join(data[-max_lines:]) if data else "", "")


def cmd_drops(backend: FirewallBackend, count: int = 20) -> str:
    raw, err = _read_log_tail(backend.log_path(), max_lines=max(count * 4, 200))
    if raw is None:
        return err
    drops = [ln for ln in raw.splitlines() if " DROP " in ln]
    if not drops:
        return "📭 אין אירועי DROP ביומן חומת האש."
    selected = drops[-count:]
    lines = [f"🚨 {count} אירועי DROP אחרונים:", ""]
    lines.extend(selected)
    return "\n".join(lines)


def cmd_stats(backend: FirewallBackend) -> str:
    list_out = cmd_list(backend)
    if list_out.startswith("📭"):
        active_count = 0
    else:
        active_count = sum(1 for ln in list_out.splitlines() if ln.startswith("• "))

    raw, err = _read_log_tail(backend.log_path(), max_lines=2000)
    if raw is None:
        last_drop = "(log unavailable)"
        total_drops = 0
        top_src: list[tuple[str, int]] = []
    else:
        drops = [ln for ln in raw.splitlines() if " DROP " in ln]
        total_drops = len(drops)
        last_drop = (
            drops[-1].split(" ", 1)[0] + " " + drops[-1].split(" ", 2)[1]
            if drops else "(none)"
        )
        from collections import Counter
        srcs = Counter()
        for ln in drops:
            parts = ln.split()
            if len(parts) >= 5:
                srcs[parts[4]] += 1
        top_src = srcs.most_common(5)

    lines = [
        "🔥 Firewall Stats",
        f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        f"🛡️  Active SENTINEL blocks : {active_count}",
        f"📉 DROP events (recent log): {total_drops}",
        f"🕒 Last DROP timestamp     : {last_drop}",
    ]
    if top_src:
        lines.append("")
        lines.append("🔝 Top sources of DROP:")
        for ip, n in top_src:
            lines.append(f"  • {ip}  ({n})")
    return "\n".join(lines)
