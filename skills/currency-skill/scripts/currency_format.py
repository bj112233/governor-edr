"""Currency skill formatters — Markdown rendering for conversion/rates/timeseries.

Extracted from currency.py (SRP).
"""


def _flag(code: str) -> str:
    """Map ISO-4217 currency code to a flag emoji using first two letters."""
    code = code.upper()
    if code == "XDR":
        return "🏛️"
    if len(code) >= 2 and "A" <= code[0] <= "Z" and "A" <= code[1] <= "Z":
        return chr(0x1F1E6 + ord(code[0]) - ord("A")) + chr(
            0x1F1E6 + ord(code[1]) - ord("A")
        )
    return ""


CURRENCY_CODES = (
    "AED AFA AFN ALL AMD ANG AOA ARS AUD AWG AZN BAM BBD BDT BGN BHD BIF BMD BND BOB BRL "
    "BSD BTN BWP BYN BZD CAD CDF CHF CLF CLP CNH CNY COP CRC CUC CUP CVE CZK DJF DKK DOP "
    "DZD EGP ERN ETB EUR FJD FKP FOK GBP GEL GGP GHS GIP GMD GNF GTQ GYD HKD HNL HRK HTG "
    "HUF IDR ILS IMP INR IQD IRR ISK JEP JMD JOD JPY KES KGS KHR KID KMF KPW KRW KWD KYD "
    "KZT LAK LBP LKR LRD LSL LYD MAD MDL MGA MKD MMK MNT MOP MRU MUR MVR MWK MXN MYR MZN "
    "NAD NGN NIO NOK NPR NZD OMR PAB PEN PGK PHP PKR PLN PYG QAR RON RSD RUB RWF SAR SBD "
    "SCR SDG SEK SGD SHP SLE SLL SOS SRD SSP STN SYP SZL THB TJS TMT TND TOP TRY TTD TVD "
    "TWD TZS UAH UGX USD UYU UZS VEF VES VND VUV WST XAF XAG XAU XCD XCG XDR XOF XPD XPF "
    "XPT YER ZAR ZMW ZWL"
).split()

CURRENCY_FLAGS = {c: _flag(c) for c in CURRENCY_CODES}


def format_timeseries_md(data: dict, frm: str, to: str) -> str:
    rates = data.get("rates", {}) or {}
    if not rates:
        return f"❌ אין נתונים בתקופה {data.get('start_date')} → {data.get('end_date')}"
    keys = sorted(rates.keys())
    first_val = list(rates[keys[0]].values())[0]
    last_val = list(rates[keys[-1]].values())[0]
    change = last_val - first_val
    pct = 100 * change / first_val if first_val else 0
    arrow = "📈" if change > 0 else ("📉" if change < 0 else "➖")
    lines = [
        f"# 📊 שינוי שער {frm.upper()} → {to.upper()}",
        f"_תקופה: {keys[0]} → {keys[-1]} ({len(keys)} ימים)_\n",
        f"- **התחלה:** 1 {frm.upper()} = {first_val:.4f} {to.upper()}",
        f"- **סוף:** 1 {frm.upper()} = {last_val:.4f} {to.upper()}",
        f"- **שינוי:** {arrow} {change:+.4f} ({pct:+.2f}%)",
        "",
        "## דגימות אחרונות",
        f"| תאריך | 1 {frm.upper()} = ? {to.upper()} |",
        "|--------|-----|",
    ]
    for d in keys[-10:]:
        v = list(rates[d].values())[0]
        lines.append(f"| {d} | {v:.4f} |")
    return "\n".join(lines)


def format_conversion_md(data: dict, amount: float, frm: str, to: str) -> str:
    rates = data.get("rates", {})
    result = rates.get(to.upper())
    if result is None:
        return f"❌ Conversion failed. Response: {data}"
    rate = result / amount if amount else 0
    flag_from = CURRENCY_FLAGS.get(frm.upper(), "")
    flag_to = CURRENCY_FLAGS.get(to.upper(), "")
    source = data.get("_source", "ECB (Frankfurter)")

    _CRYPTO = {"BTC", "ETH", "LTC", "XRP", "ADA", "DOT", "DOGE", "SOL", "AVAX", "MATIC", "BNB", "USDT", "USDC", "BUSD"}
    is_crypto = to.upper() in _CRYPTO
    if is_crypto or result < 0.01:
        result_fmt = f"{result:,.8f}"
        rate_fmt = f"{rate:.8f}"
    else:
        result_fmt = f"{result:,.2f}"
        rate_fmt = f"{rate:.4f}"

    # Inverse rate for tiny fractions — pre-compute so the LLM doesn't have to.
    # SLMs (4B) hallucinate when asked to divide 1 / 0.00001562.
    # We do it in Python (CPU) and inject the human-readable line directly.
    inverse_line = ""
    if rate > 0 and rate < 0.01:
        inverse = 1.0 / rate
        inverse_line = f"- שער הפוך: 1 {to.upper()} = {inverse:,.2f} {frm.upper()}\n"

    return (
        f"# 💱 המרת מטבע\n\n"
        f"**{flag_from} {amount:,.2f} {frm.upper()}** = "
        f"**{flag_to} {result_fmt} {to.upper()}**\n\n"
        f"- שער: 1 {frm.upper()} = {rate_fmt} {to.upper()}\n"
        f"{inverse_line}"
        f"- תאריך: {data.get('date', 'latest')}\n"
        f"- מקור: {source}"
    )


def format_rates_md(data: dict) -> str:
    base = data.get("base", "?")
    rates = data.get("rates", {})
    flag = CURRENCY_FLAGS.get(base.upper(), "")
    source = data.get("_source", "ECB (Frankfurter)")
    lines = [
        f"# 💱 שערי חליפין מול {flag} {base.upper()}",
        f"_תאריך: {data.get('date', 'latest')} | מקור: {source}_\n",
        "| מטבע | שער (1 " + base + " =) |",
        "|--------|-----|",
    ]
    for cur, val in sorted(rates.items()):
        flag_to = CURRENCY_FLAGS.get(cur, "")
        lines.append(f"| {flag_to} {cur} | {val:.4f} |")
    return "\n".join(lines)
