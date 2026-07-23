"""Watchlist state management + price-target triggers."""

import json

from _stocks_utils import TARGETS_FILE, WATCHLIST_FILE
from stocks_quotes import get_quote
from stocks_render import cmd_quote


def load_watchlist() -> list:
    try:
        return json.loads(WATCHLIST_FILE.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_watchlist(symbols: list) -> None:
    WATCHLIST_FILE.write_text(
        json.dumps(sorted(set(symbols)), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def load_targets() -> dict:
    """Map symbol -> {target: float, direction: 'above'|'below'}."""
    try:
        return json.loads(TARGETS_FILE.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_targets(targets: dict) -> None:
    TARGETS_FILE.write_text(
        json.dumps(targets, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def _normalize_wl(wl: list) -> list:
    """Backward-compat: legacy watchlists were plain string lists; new format keeps strings."""
    out = []
    for s in wl:
        if isinstance(s, str) and s.strip():
            out.append(s.strip().upper())
    return sorted(set(out))


def _wl_list(wl: list, targets: dict) -> str:
    if not wl:
        return "📋 Watchlist ריק. הוסף עם: --action add --symbol AAPL"
    lines = ["# 👁️ Watchlist\n"]
    for s in wl:
        tgt = targets.get(s)
        if tgt:
            lines.append(f"- {s}  —  🎯 target {tgt['direction']} {tgt['target']}")
        else:
            lines.append(f"- {s}")
    return "\n".join(lines)


def _wl_add(
    wl: list, symbols: list | None, target: float | None, direction: str
) -> str:
    if not symbols:
        return "❌ דורש --symbol"
    added = [s.strip().upper() for s in symbols if s.strip()]
    wl = sorted(set(wl + added))
    save_watchlist(wl)
    if target is not None and added:
        targets = load_targets()
        for s in added:
            targets[s] = {"target": float(target), "direction": direction}
        save_targets(targets)
        return f'✅ נוסף. סה"כ: {len(wl)} סמלים; target {direction} {target} נשמר.'
    return f'✅ נוסף. סה"כ: {len(wl)} סמלים.'


def _wl_remove(wl: list, symbols: list | None) -> str:
    if not symbols:
        return "❌ דורש --symbol"
    to_remove = {s.strip().upper() for s in symbols if s.strip()}
    wl = [s for s in wl if s not in to_remove]
    save_watchlist(wl)
    targets = load_targets()
    for s in to_remove:
        targets.pop(s, None)
    save_targets(targets)
    return f"✅ הוסר. נשארו {len(wl)} סמלים."


def _wl_quotes(wl: list) -> str:
    if not wl:
        return "📋 Watchlist ריק."
    return cmd_quote(wl)


def _wl_check(wl: list, targets: dict, fmt: str) -> str:
    """Iterate watchlist, evaluate price-target triggers."""
    triggered = []
    for sym in wl:
        t = targets.get(sym)
        if not t:
            continue
        q = get_quote(sym)
        price = q.get("price")
        if price is None:
            continue
        tgt = float(t["target"])
        d = t.get("direction", "below")
        if (d == "below" and price <= tgt) or (d == "above" and price >= tgt):
            triggered.append(
                {
                    "symbol": sym,
                    "price": price,
                    "target": tgt,
                    "direction": d,
                    "currency": q.get("currency"),
                }
            )
    if fmt == "json":
        return json.dumps({"triggered": triggered}, ensure_ascii=False, indent=2)
    if not triggered:
        return "✅ אין טריגרים פעילים."
    out = ["# 🚨 Watchlist Triggers\n"]
    for t in triggered:
        out.append(
            f"- **{t['symbol']}** {t['currency']} {t['price']:.2f} "
            f"— חצה יעד ({t['direction']} {t['target']})"
        )
    return "\n".join(out)


def cmd_watchlist(
    action: str,
    symbols: list | None,
    target: float | None = None,
    direction: str = "below",
    fmt: str = "markdown",
) -> str:
    wl = _normalize_wl(load_watchlist())
    if action == "list":
        return _wl_list(wl, load_targets())
    if action == "add":
        return _wl_add(wl, symbols, target, direction)
    if action == "remove":
        return _wl_remove(wl, symbols)
    if action == "quotes":
        return _wl_quotes(wl)
    if action == "check":
        return _wl_check(wl, load_targets(), fmt)
    return f"❌ Unknown action: {action}"
