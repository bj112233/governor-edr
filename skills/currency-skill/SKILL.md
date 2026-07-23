---
name: currency-skill
description: "FASTEST tool for exchange rates + currency conversion, including crypto (BTC, ETH, USDT). Use this for any price question: 'כמה שווה ביטקוין', 'שער דולר', 'המר 100 יורו לשקל'. Sources: Frankfurter/ECB, exchangerate-api.com, fawazahmed0 (crypto). No API key. Command 'python', args 'scripts/currency.py --amount N --from USD --to ILS'. Always fetch live. Do NOT use stocks-skill for simple price questions — use this instead."
metadata: {"clawdbot":{"emoji":"💱","commands":["run"],"arg_template":"scripts/currency.py {args}","requires":{"bins":["python"],"python_libs":["requests"]},"install":[{"id":"pip-currency","kind":"pip","packages":["requests"],"label":"Currency skill deps"}],"commands_schema":{"run":{"properties":{"amount":{"type":"number","description":"Amount to convert (default: 1)"},"from":{"type":"string","description":"Source currency code (e.g. USD, EUR, ILS, BTC)"},"to":{"type":"string","description":"Target currency code (e.g. USD, EUR, ILS, BTC)"},"amounts":{"type":"string","description":"Comma-separated amounts for batch conversion (e.g. \"100,500,1000\")"},"rates":{"type":"string","description":"Base currency for full rate table (e.g. ILS)"},"date":{"type":"string","description":"Historical date YYYY-MM-DD (Frankfurter only)"},"start":{"type":"string","description":"Start date for trend analysis YYYY-MM-DD"},"end":{"type":"string","description":"End date for trend analysis YYYY-MM-DD"},"format":{"type":"string","enum":["markdown","json"],"default":"markdown"},"output":{"type":"string","description":"Optional output file path"}}}}}}
---

# Currency Skill

המרת מטבעות + שערי חליפין משלוש מקורות חינמיים (ללא API key). שרשרת fallback חכמה לפי target:

1. **Frankfurter / ECB** — primary, fiat רשמי, היסטוריה מ-1999.
2. **exchangerate-api.com v6** (open.er-api.com) — 160+ fiat, real-time, latest only. [Attribution required](https://www.exchangerate-api.com/terms).
3. **fawazahmed0/currency-api** — 200+ כולל קריפטו (BTC/ETH/USDT/...), CDN jsDelivr.

אם target לא קיים במקור מוקדם יותר — ה-skill עובר אוטומטית למקור הבא.

## יכולות

| יכולת | פרמטרים | תיאור |
|-------|---------|-------|
| המרה יחידה | `--amount N --from X --to Y` | המרת סכום בודד בין מטבעות |
| המרות מרובות | `--amounts "100,500,1000" --from X --to Y` | מספר סכומים בקריאה אחת |
| שערים מלאים | `--rates BASE` | כל השערים מול מטבע בסיס |
| המרת קריפטו | `--from USD --to BTC` | קריפטו (BTC, ETH, USDT, וכו') דרך fawazahmed0 |
| שער היסטורי | `--date YYYY-MM-DD` | שער בתאריך עבר (Frankfurter) |
| מגמת שער | `--start DATE --end DATE --from X --to Y` | ניתוח שינוי שער לאורך זמן |
| פלט JSON | `--format json` | פלט מכונה לעיבוד |
| שמירה לקובץ | `--output path` | כתיבת תוצאה לקובץ |

## דוגמאות שימוש

```bash
# המרה ישירה
python {baseDir}/scripts/currency.py --amount 1500 --from USD --to ILS
python {baseDir}/scripts/currency.py --amount 100 --from EUR --to USD

# המרות מרובות
python {baseDir}/scripts/currency.py --amounts "100,500,1000" --from USD --to ILS

# כל השערים מול שקל (160+ מטבעות)
python {baseDir}/scripts/currency.py --rates ILS

# שער היסטורי
python {baseDir}/scripts/currency.py --amount 1000 --from USD --to ILS --date 2024-01-01

# מגמת שער (30 יום)
python {baseDir}/scripts/currency.py --start 2024-01-01 --end 2024-01-30 --from USD --to ILS

# המרה לקריפטו (חדש 2026)
python {baseDir}/scripts/currency.py --amount 1000 --from USD --to BTC
python {baseDir}/scripts/currency.py --amount 5000 --from USD --to ETH

# פלט JSON
python {baseDir}/scripts/currency.py --amount 100 --from USD --to ILS --format json

# שמירה לקובץ
python {baseDir}/scripts/currency.py --amount 1000 --from EUR --to ILS --output rates.md
```

## מטבעות נתמכים (160+)

USD, EUR, ILS, GBP, JPY, CHF, CAD, AUD, CNY, INR, RUB, BRL, TRY, MXN, KRW, SGD, HKD, SEK, NOK, DKK, PLN, ZAR, AED, AFN, ALL, AMD, ANG, AOA, ARS, AWG, AZN, BAM, BBD, BDT, BGN, BHD, BIF, BMD, BND, BOB, BSD, BTN, BWP, BYN, BZD, CDF, CLP, COP, CRC, CUP, CVE, CZK, DJF, DOP, DZD, EGP, ERN, ETB, FJD, FKP, FOK, GEL, GGP, GHS, GIP, GMD, GNF, GTQ, GYD, HNL, HRK, HTG, HUF, IDR, IMP, IQD, IRR, ISK, JMD, JOD, KES, KGS, KHR, KID, KMF, KWD, KYD, KZT, LAK, LBP, LKR, LRD, LSL, LYD, MAD, MDL, MGA, MKD, MMK, MNT, MOP, MRU, MUR, MVR, MWK, MYR, MZN, NAD, NGN, NIO, NPR, NZD, OMR, PAB, PEN, PGK, PHP, PKR, PYG, QAR, RON, RSD, RWF, SAR, SBD, SCR, SDG, SHP, SLE, SLL, SOS, SRD, SSP, STN, SYP, SZL, TJS, TMT, TND, TOP, TTD, TVD, TWD, TZS, UAH, UGX, UYU, UZS, VED, VES, VND, VUV, WST, XAF, XCD, XCG, XDR, XOF, XPF, YER, ZMW, ZWL

**מקורות (בסדר עדיפות)**:
1. ECB / Frankfurter — fiat רשמי, היסטוריה מלאה.
2. exchangerate-api.com v6 Open Access — 160+ fiat real-time. Attribution required per [terms](https://www.exchangerate-api.com/terms).
3. fawazahmed0/currency-api — 200+ כולל קריפטו (jsDelivr CDN).

כל המקורות חינמיים לחלוטין, ללא API key.

> ⚠️ **Attribution:** exchangerate-api.com v6 Open Access requires attribution per [terms of use](https://www.exchangerate-api.com/terms). Data may be cached but not redistributed.
