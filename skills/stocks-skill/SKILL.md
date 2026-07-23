---
name: stocks-skill
description: "Stock DEPTH analysis only: Volume, 52-Week High/Low, Market Cap, P/E, news, watchlist. Use ONLY when user needs detailed stock metrics — NOT for simple price questions (use currency-skill for those). Sources: Finnhub (real-time US, 60/min) when FINNHUB_API_KEY set, else yfinance (Yahoo Finance, free). Command 'python', args 'scripts/stocks.py quote --symbol AAPL,NVDA,MSFT' or 'scripts/stocks.py history --symbol AAPL --period 1mo' or 'scripts/stocks.py watchlist add/list/remove --symbol X'. Trigger: מניות, stock, ticker, NVDA, AAPL, S&P, NASDAQ, ת\"א 35, watchlist, P/E, market cap. Always fetch live."
metadata: {"clawdbot":{"emoji":"📈","commands":["quote","history","news","crypto","watchlist"],"arg_template":"scripts/stocks.py {command} {args}","requires":{"bins":["python"],"python_libs":["yfinance","pandas"]},"install":[{"id":"pip-stocks","kind":"pip","packages":["yfinance","pandas"],"label":"Stocks skill deps"}],"commands_schema":{"quote":{"properties":{"symbol":{"type":"string","description":"Comma-separated ticker symbols (e.g. AAPL,NVDA,MSFT)"},"format":{"type":"string","enum":["markdown","json"],"default":"markdown"}},"required":["symbol"]},"history":{"properties":{"symbol":{"type":"string","description":"Single ticker symbol (e.g. AAPL)"},"period":{"type":"string","enum":["1d","5d","1mo","3mo","6mo","1y","2y","5y","10y","max"],"default":"1mo"},"output":{"type":"string","description":"Optional CSV output filename"}},"required":["symbol"]},"news":{"properties":{"symbol":{"type":"string","description":"Ticker symbol (e.g. AAPL)"},"limit":{"type":"integer","default":10}},"required":["symbol"]},"crypto":{"properties":{"symbol":{"type":"string","description":"Crypto pair (e.g. BTC-USD, ETH-USD)"}},"required":["symbol"]},"watchlist":{"properties":{"action":{"type":"string","enum":["add","list","remove","quotes","check"],"description":"Watchlist action"},"symbol":{"type":"string","description":"Comma-separated symbols for add/remove"},"target":{"type":"number","description":"Price target for alerts"},"direction":{"type":"string","enum":["above","below"],"description":"Alert direction"}},"required":["action"]}}}}
---

# Stocks Skill

מחירי מניות real-time + היסטוריה + watchlist עם persistent state.

## מקורות (בסדר עדיפות)

1. **Finnhub** — real-time US stocks, 60 calls/min חינמי. מקור עיקרי כשמוגדר `FINNHUB_API_KEY`. גם מחזיר שם חברה מלא, P/E, market cap.
2. **yfinance (Yahoo Finance)** — fallback טבעי. ללא key. משמש גם למניות לא-אמריקניות (תל-אביב `.TA`) ולזוגות קריפטו (BTC-USD).
3. פקודות `history`, `news`, `crypto` תמיד דרך yfinance.

## משתני סביבה

| Var | תפקיד | חובה? |
|---|---|---|
| `FINNHUB_API_KEY` | מפתח Finnhub (חינמי, https://finnhub.io/register) | מומלץ — משפר מדויקות ל-US stocks |

## Quick start

```bash
# מחיר נוכחי
python {baseDir}/scripts/stocks.py quote --symbol AAPL
python {baseDir}/scripts/stocks.py quote --symbol "NVDA,AAPL,MSFT,GOOGL"

# היסטוריה
python {baseDir}/scripts/stocks.py history --symbol NVDA --period 1mo
python {baseDir}/scripts/stocks.py history --symbol TSLA --period 1y --output tsla.csv

# חדשות מניה
python {baseDir}/scripts/stocks.py news --symbol AAPL --limit 10

# קריפטו דרך Yahoo Finance
python {baseDir}/scripts/stocks.py crypto --symbol BTC-USD
python {baseDir}/scripts/stocks.py crypto --symbol ETH-USD

# Watchlist
python {baseDir}/scripts/stocks.py watchlist --action add --symbol "NVDA,AAPL,MSFT"
python {baseDir}/scripts/stocks.py watchlist --action add --symbol "AAPL" --target 180 --direction above
python {baseDir}/scripts/stocks.py watchlist --action list
python {baseDir}/scripts/stocks.py watchlist --action remove --symbol AAPL
python {baseDir}/scripts/stocks.py watchlist --action quotes  # current quotes for all watched
python {baseDir}/scripts/stocks.py watchlist --action check   # check price targets

# מניות תל אביב (יש להוסיף .TA)
python {baseDir}/scripts/stocks.py quote --symbol "TEVA.TA,POLI.TA,LUMI.TA"
```

## Periods נתמכים
1d, 5d, 1mo, 3mo, 6mo, 1y, 2y, 5y, 10y, ytd, max
