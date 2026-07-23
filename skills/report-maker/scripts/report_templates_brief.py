"""Report Maker briefing templates — briefing, daily digest, contract.

Extracted from report_templates.py (SRP).
"""
from datetime import datetime

from report_templates_base import _format_list_item


def _briefing_template(items, raw: str) -> str:
    """Executive briefing: top highlights + bullet summary."""
    lines = ["## 📌 תקציר מנהלים\n"]
    if items:
        highlights = items[:3]
        for it in highlights:
            if isinstance(it, dict):
                title = it.get("title") or it.get("name") or str(it)[:80]
                summary = (
                    it.get("summary") or it.get("description")
                    or it.get("snippet") or ""
                )
                lines.append(f"### {title}")
                if summary:
                    lines.append(str(summary)[:400])
                if it.get("link"):
                    lines.append(f"[קישור]({it['link']})")
                lines.append("")
            else:
                lines.append(f"- {it}")
        if len(items) > 3:
            lines.append("\n## פריטים נוספים\n")
            for it in items[3:]:
                lines.append(_format_list_item(it))
    else:
        lines.append(raw[:2000])
    return "\n".join(lines)


_SEVERITY_ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "WARNING": "🟡", "INFO": "🔵"}


def _format_alerts_section(alerts: list) -> list[str]:
    """Format alerts section with severity icons."""
    if not alerts:
        return []
    lines = ["## 🚨 התראות"]
    for a in alerts[:10]:
        sev = a.get("severity", "info").upper()
        icon = _SEVERITY_ICONS.get(sev, "⚪")
        lines.append(f"- {icon} **{a.get('type', 'Alert')}** — {a.get('message', '')}")
    lines.append("")
    return lines


def _format_market_section(market: list) -> list[str]:
    """Format market data section with change arrows."""
    if not market:
        return []
    lines = ["## 💹 שוק ההון", "| סמל | מחיר | שינוי |", "|------|------|--------|"]
    for m in market[:15]:
        ch = m.get("change", 0)
        arrow = (
            "📈" if (isinstance(ch, (int, float)) and ch > 0)
            else ("📉" if (isinstance(ch, (int, float)) and ch < 0) else "➖")
        )
        lines.append(f"| {m.get('symbol', '')} | {m.get('price', '')} | {arrow} {ch} |")
    lines.append("")
    return lines


def _format_news_section(news: list) -> list[str]:
    """Format news headlines section."""
    if not news:
        return []
    lines = ["## 📰 חדשות מובילות"]
    for n in news[:15]:
        title = n.get("title", "")
        link = n.get("link", "")
        summary = (n.get("summary") or "")[:200]
        lines.append(f"- [{title}]({link})" if link else f"- {title}")
        if summary:
            lines.append(f"  - {summary}")
    lines.append("")
    return lines


def _format_tasks_section(tasks: list) -> list[str]:
    """Format action items section."""
    if not tasks:
        return []
    lines = ["## ✅ משימות / Action Items"]
    for t in tasks:
        lines.append(f"- [ ] {t}")
    lines.append("")
    return lines


def _daily_digest_template(items, raw: str) -> str:
    """R1: Daily digest combining news + alerts + market data into a single report."""
    if not isinstance(items, dict):
        items = {}
    today = datetime.now().strftime("%d/%m/%Y")
    lines = [f"# 📅 דייג'סט יומי — {today}\n"]

    lines.extend(_format_alerts_section(items.get("alerts")))
    lines.extend(_format_market_section(items.get("market")))
    lines.extend(_format_news_section(items.get("news")))
    lines.extend(_format_tasks_section(items.get("tasks")))

    if len(lines) == 1:
        lines.append("_אין נתונים. ספק JSON עם אחד המפתחות: news, alerts, market, tasks._\n")
        lines.append(raw[:1500])
    return "\n".join(lines)


def _contract_template(items, raw: str) -> str:
    """R2: Professional contract analysis report."""
    if not isinstance(items, dict):
        return raw[:2000]
    lines = [f"# 📄 ניתוח חוזה: {items.get('filename', '—')}\n"]
    contract_type = items.get("type", "כללי")
    lines.append(f"**סוג חוזה:** {contract_type}  ")
    lines.append(f"**תאריך ניתוח:** {datetime.now().strftime('%d/%m/%Y %H:%M')}\n")

    clauses = items.get("clauses", [])
    if clauses:
        lines.append("## 📋 סעיפים מזוהים\n")
        lines.append("| סעיף | סטטוס | תיאור |")
        lines.append("|------|-------|--------|")
        score_icon = {"good": "✅ טוב", "bad": "❌ רע", "neutral": "⚪ ניטרלי"}
        for c in clauses:
            label = score_icon.get(c.get("score", "neutral"), "⚪")
            desc = (c.get("description") or "")[:120]
            lines.append(f"| {c.get('name', '')} | {label} | {desc} |")
        lines.append("")

    summary = items.get("summary", {})
    if summary.get("good"):
        lines.append("## ✅ סעיפים טובים")
        for s in summary["good"]:
            lines.append(f"- {s}")
        lines.append("")
    if summary.get("bad"):
        lines.append("## ❌ דורש תשומת לב")
        for s in summary["bad"]:
            lines.append(f"- ⚠️ {s}")
        lines.append("")

    good_count = len(summary.get("good", []))
    bad_count = len(summary.get("bad", []))
    score = good_count - bad_count
    verdict = (
        "✅ נראה טוב" if score > 1 else ("⚠️ דורש בדיקה" if score >= -1 else "❌ בעייתי")
    )
    lines.append(f"\n## סיכום\n\n**ציון:** {good_count} טוב / {bad_count} רע → {verdict}\n")
    return "\n".join(lines)
