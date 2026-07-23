"""Digest formatter — A+ minimal format with box-drawing separators.

Pure Markdown generation, no side effects, no network.
"""

import re
from datetime import datetime
from urllib.parse import urlparse

_CATEGORY_EMOJIS = {
    "news_il": "\U0001f1ee\U0001f1f1",
    "tech_ai": "\U0001f4bb",
    "cyber": "\U0001f512",
    "economy_il": "\U0001f4b0",
    "world": "\U0001f30d",
    "security_mil": "\U0001f6e1\ufe0f",
    "politics_il": "\U0001f3db\ufe0f",
    "sports": "\u26bd",
    "health": "\U0001f3e5",
    "auto": "\U0001f697",
    "realestate": "\U0001f3e0",
}

_CATEGORY_LABELS = {
    "news_il": "חדשות",
    "tech_ai": "טכנולוגיה",
    "cyber": "סייבר",
    "economy_il": "כלכלה",
    "world": "עולם",
    "security_mil": "ביטחון",
    "politics_il": "פוליטיקה",
    "sports": "ספורט",
    "health": "בריאות",
    "auto": "רכב",
    "realestate": 'נדל"ן',
}

# Display order: security first, then by relevance
_CATEGORY_ORDER = (
    "security_mil",
    "news_il",
    "politics_il",
    "economy_il",
    "cyber",
    "tech_ai",
    "world",
    "health",
    "auto",
    "realestate",
    "sports",
)

_SEP = "\u2500" * 25  # ──────────────────────────


def format_digest(categorized_items: dict[str, list[dict]]) -> str:
    """Format news digest as A+ Markdown. Pure function — no I/O."""
    from services.time_format import format_feed_time_short as _fmt_date

    lines: list[str] = []
    header_date = datetime.now().strftime("%d/%m/%Y")

    # Box-drawing header
    lines.append(
        "\u256d\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"
        "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\U0001f4f0\u2500"
        "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"
        "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u256e"
    )
    lines.append(
        f"\u2502        \u05e2\u05d3\u05db\u05d5\u05df \u05d9\u05d5\u05de\u05d9 \u00b7 {header_date}        \u2502"
    )
    lines.append("\u2570" + "\u2500" * 39 + "\u256f")
    lines.append("")

    total_items = 0

    # Sort categories by _CATEGORY_ORDER, unknowns last
    sorted_cats = sorted(
        categorized_items.items(),
        key=lambda kv: _CATEGORY_ORDER.index(kv[0]) if kv[0] in _CATEGORY_ORDER else 999,
    )

    for category, items in sorted_cats:
        if not items:
            continue
        total_items += len(items)
        emoji = _CATEGORY_EMOJIS.get(category, "\U0001f4f0")
        label = _CATEGORY_LABELS.get(category, category.replace("_", " ").title())
        lines.append(f"{emoji} {label} {_SEP}")
        lines.append("")

        for item in items[:10]:
            _format_item_a_plus(lines, item, _fmt_date)
            lines.append("")

    # Footer with stats
    lines.append("\u2501" * 40)
    lines.append(
        f"\U0001f4ca {len(sorted_cats)} \u05e7\u05d8\u05d2\u05d5\u05e8\u05d9\u05d5\u05ea \u00b7 {total_items} \u05e4\u05e8\u05d9\u05d8\u05d9\u05dd \u00b7 24h"
    )
    return "\n".join(lines)


def _format_item_a_plus(lines: list[str], item: dict, _fmt_date) -> None:
    """Append A+ formatted item (mutates lines list)."""
    title = item.get("title", "").strip()
    link = item.get("link", "").strip()
    source = item.get("source", "").strip()
    summary = item.get("summary", "").strip()
    date_raw = item.get("published", "").strip()

    if not title:
        return

    lines.append(f"  \u25b8 {title}")

    # Meta line: source · date
    meta_parts = [p for p in (source, _fmt_date(date_raw)) if p]
    if meta_parts:
        lines.append(f"    {' \u00b7 '.join(meta_parts)}")

    # Summary (RSS raw, truncated)
    if summary:
        lines.append(f"    {_truncate(summary, 180)}")

    # Domain-only link
    if link:
        domain = _extract_domain(link)
        if domain:
            lines.append(f"    \u2197 {domain}")


def _extract_domain(url: str) -> str:
    """Extract clean domain from URL (no scheme, no path)."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split("/")[0]
        # Strip www.
        if domain.startswith("www."):
            domain = domain[4:]
        # Must contain a dot to be a real domain
        if "." not in domain:
            return ""
        return domain
    except Exception:
        return ""


def _truncate(text: str, max_len: int) -> str:
    """Truncate text at last space boundary."""
    if len(text) <= max_len:
        return text
    trunc = text[:max_len]
    if " " in trunc:
        trunc = trunc.rsplit(" ", 1)[0]
    return trunc + "..."
