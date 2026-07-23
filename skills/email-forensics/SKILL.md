---
name: email-forensics
description: "Phishing & email forensics analysis. Parses .eml (Python stdlib) and .msg (Outlook, via extract-msg) files. Extracts SPF/DKIM/DMARC verdicts from Authentication-Results headers, parses the Received routing chain (who sent to whom, hops, timestamps), and extracts URLs/IPs/email addresses from the body for IOC chaining to intel-skill. Trigger when user asks to analyze a phishing email, check email authentication, trace email routing, extract IOCs from an .eml/.msg file, or investigate a suspicious email."
metadata:
  clawdbot:
    emoji: "📧"
    commands: [headers, auth, route, urls, full]
    arg_template: "scripts/eml_analyst.py {command} {args}"
    timeout: 30
    requires:
      bins: [python]
      python_libs: [html2text]
    install:
      - id: pip-email-core
        kind: pip
        packages: [html2text]
        label: "Install html2text for HTML body parsing (core)"
      - id: pip-email-msg
        kind: pip
        optional: true
        packages: [extract-msg, dkimpy]
        label: "Optional: .msg (Outlook) support + DKIM verification"
    commands_schema:
      headers:
        properties:
          path:
            type: string
            description: "Path to .eml or .msg file"
        required: [path]
      auth:
        properties:
          path:
            type: string
            description: "Path to .eml or .msg file"
        required: [path]
      route:
        properties:
          path:
            type: string
            description: "Path to .eml or .msg file"
        required: [path]
      urls:
        properties:
          path:
            type: string
            description: "Path to .eml or .msg file"
        required: [path]
      full:
        properties:
          path:
            type: string
            description: "Path to .eml or .msg file"
          chain:
            type: boolean
            default: false
            description: "Format output as chainable IOC JSON for intel-skill enrichment"
        required: [path]
---

# Email Forensics — Phishing & EML analysis

ניתוח פורנזי של קבצי אימייל (.eml / .msg) לזיהוי פישינג וחילוץ IOCs.
מפרק את תשתית התוקף: אימות SPF/DKIM/DMARC, נתיב ניתוב, וכתובות זדוניות בגוף.

## יכולות

- **SPF/DKIM/DMARC** — קורא את `Authentication-Results` header (השרת המקבל כבר אימת)
- **Received chain** — מפרק את נתיב הניתוב: מי→מי, כמה hops, timestamps
- **Key headers** — From, Reply-To, Return-Path, X-Originating-IP, X-Mailer, X-Spam-Status
- **Body IOCs** — URLs, IPs, וכתובות אימייל מהגוף (text + HTML)
- **שרשור ל-intel-skill** — פלט JSON עם domains/IPs/URLs להעשרת OSINT

## Quick start

```bash
# כל ה-headers הפורנזיים
python {baseDir}/scripts/eml_analyst.py headers --path ~/Downloads/suspicious.eml

# אימות SPF/DKIM/DMARC בלבד
python {baseDir}/scripts/eml_analyst.py auth --path ~/Downloads/suspicious.eml

# נתיב ניתוב (Received chain)
python {baseDir}/scripts/eml_analyst.py route --path ~/Downloads/suspicious.eml

# URLs/IPs מהגוף
python {baseDir}/scripts/eml_analyst.py urls --path ~/Downloads/suspicious.eml

# ניתוח מלא + שרשור ל-intel-skill
python {baseDir}/scripts/eml_analyst.py full --path ~/Downloads/suspicious.eml --chain

# קובץ Outlook .msg (דורש extract-msg)
python {baseDir}/scripts/eml_analyst.py full --path ~/Outlook/suspicious.msg --chain
```

## פקודות נתמכות

| פקודה | תיאור | פלט |
|-------|-------|-----|
| `headers` | כל ה-headers הפורנזיים | טקסט מפורמט |
| `auth` | SPF/DKIM/DMARC verdicts | טקסט עם ✅/❌/⚠️ |
| `route` | נתיב ניתוב (Received chain) | רשימת hops |
| `urls` | URLs/IPs/emails מהגוף | רשימה מקוטגרת |
| `full` | ניתוח מלא | טקסט + JSON (עם `--chain`) |

## שרשור ל-intel-skill

הפלט של `full --chain` מסתיים ב-JSON בפרוטוקול המשותף:
```json
{
  "iocs": {"domains": ["..."], "ips": ["..."], "urls": ["..."], "hashes": []},
  "source": "email-forensics",
  "chain_to": "intel-skill",
  "stats": {"raw_domains": 20, "raw_ips": 8, "filtered_domains": 5, "filtered_ips": 3, "selected_total": 8},
  "triage": "📊 Triage Report: Extracted 28 raw IOCs. Filtered out 20 (private/benign). Selected top 8 for analysis."
}
```
העבר את ה-domains/IPs/URLs ל-`intel-skill sweep` או `intel-skill cluster` להעשרת OSINT.

## Triage — סינון דטרמיניסטי לפני העשרה

שכבת סינון אוטומטית (`skills/_shared/ioc_triage.py`) פועלת לפני בניית ה-JSON:

1. **Private IPs** — RFC1918 + loopback + link-local → מוסרים (כבר קיים ב-`_body_extractor`)
2. **Benign domains** — שורשי דומיינים לגיטימיים (Microsoft, Google, AWS, Apple, Cloudflare, GitHub, Telegram ועוד ~25) → מוסרים
3. **Top-K Selection** — מקסימום 15 IOCs להעשרה (מיון לפי תדר יורד)

מטרה: מניעת קריסת intel-skill מ-Rate Limit (VT: 4 req/min) ו-Context Bloat ב-LLM.

## תלות

- **Core (.eml)**: Python stdlib `email` + `html2text` (מותקן)
- **Optional (.msg)**: `extract-msg` — מותקן אופציונלית, קוד מידרדר בחן אם חסר
- **Optional (DKIM verify)**: `dkimpy` — לאימות עצמאי (ברירת מחדל: קורא מ-Authentication-Results)
