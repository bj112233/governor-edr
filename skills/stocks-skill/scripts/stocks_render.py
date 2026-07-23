"""Markdown rendering for quotes, news, crypto, and history commands."""

from _stocks_utils import _safe, yf
from stocks_quotes import get_quote


def _fmt_big(v):
    """Format large numbers with T/B/M suffixes."""
    if v is None:
        return "—"
    if v >= 1e12:
        return f"{v / 1e12:.2f}T"
    if v >= 1e9:
        return f"{v / 1e9:.2f}B"
    if v >= 1e6:
        return f"{v / 1e6:.2f}M"
    return f"{v:,.0f}"


def format_quote_md(q: dict) -> str:
    cur = q["currency"]
    price = q["price"]
    chg = q["change"]
    pct = q["change_pct"]
    if price is None:
        return f"❌ אין נתונים עבור {q['symbol']}"
    arrow = "📈" if (chg or 0) > 0 else ("📉" if (chg or 0) < 0 else "➖")
    chg_str = f"{chg:+.2f} ({pct:+.2f}%)" if chg is not None else "—"
    return (
        f"## {q['symbol']} — {q['name']}\n"
        f"- **{cur} {price:,.2f}** {arrow} {chg_str}\n"
        f"- היום: {q['day_low']} → {q['day_high']}\n"
        f"- 52W: {q['fifty_two_week_low']} → {q['fifty_two_week_high']}\n"
        f"- Market Cap: {_fmt_big(q['market_cap'])} | P/E: {q['pe_ratio'] or '—'}\n"
        f"- Volume: {_fmt_big(q['volume'])}"
    )


def cmd_quote(symbols: list) -> str:
    quotes = [get_quote(s.strip()) for s in symbols if s.strip()]
    out = ["# 📈 מחירי מניות\n"]
    for q in quotes:
        out.append(format_quote_md(q))
        out.append("")
    return "\n".join(out)


def cmd_news(symbol: str, limit: int = 10) -> str:
    """Fetch recent headlines for a ticker via yfinance."""
    t = yf.Ticker(symbol)
    news = _safe(lambda: t.news, []) or []
    if not news:
        return f"📭 אין כותרות חדשות עבור {symbol.upper()}."
    lines = [f"# 📰 {symbol.upper()} — חדשות אחרונות\n"]
    for n in news[:limit]:
        title = n.get("title") or "—"
        publisher = n.get("publisher") or n.get("source") or "—"
        link = n.get("link") or n.get("url") or ""
        ts = n.get("providerPublishTime") or n.get("pubDate")
        if isinstance(ts, (int, float)):
            from datetime import datetime as _dt

            try:
                ts_str = _dt.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M")
            except (OSError, ValueError):
                ts_str = str(ts)
        else:
            ts_str = str(ts) if ts else "—"
        if link:
            lines.append(f"- [{title}]({link})")
        else:
            lines.append(f"- {title}")
        lines.append(f"  - {publisher} · {ts_str}")
    return "\n".join(lines)


def cmd_crypto(symbol: str) -> str:
    """Quote a crypto pair. yfinance accepts BTC-USD, ETH-USD, etc.
    If user passes 'BTC' alone, default to USD pair."""
    sym = symbol.strip().upper()
    if "-" not in sym:
        sym = f"{sym}-USD"
    return cmd_quote([sym])


def cmd_history(symbol: str, period: str, output: str | None) -> str:
    t = yf.Ticker(symbol)
    hist = t.history(period=period, auto_adjust=False)
    if hist.empty:
        return f"❌ אין היסטוריה עבור {symbol} ל-{period}"
    if output:
        hist.to_csv(output, encoding="utf-8")
        return f"✅ {len(hist)} שורות נשמרו ל-{output}"
    # Compact summary
    first = float(hist["Close"].iloc[0])
    last = float(hist["Close"].iloc[-1])
    change = 100 * (last - first) / first if first else 0
    lines = [
        f"# 📊 {symbol.upper()} — היסטוריה ({period})\n",
        f"- תקופה: {hist.index[0].date()} → {hist.index[-1].date()}",
        f"- שורות: {len(hist)}",
        f"- פתיחה: {first:.2f} → סגירה: {last:.2f} ({change:+.2f}%)",
        f"- שיא: {hist['High'].max():.2f}",
        f"- שפל: {hist['Low'].min():.2f}",
        f"- ממוצע נפח: {hist['Volume'].mean():,.0f}",
        "",
        "## 5 השורות האחרונות",
        "| תאריך | פתיחה | סגירה | High | Low | Volume |",
        "|--------|-------|-------|------|-----|--------|",
    ]
    for idx, row in hist.tail(5).iterrows():
        lines.append(
            f"| {idx.date()} | {row['Open']:.2f} | {row['Close']:.2f} | "
            f"{row['High']:.2f} | {row['Low']:.2f} | {row['Volume']:,.0f} |"
        )
    return "\n".join(lines)
