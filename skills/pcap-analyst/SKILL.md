---
name: pcap-analyst
description: "Streaming PCAP/network capture analysis for IOC extraction. Parses DNS queries (UDP/53) and TLS SNI (TCP/443) from .pcap/.pcapng files using scapy's PcapReader generator (never loads full capture into RAM — OOM-hardened with 50MB file gate). Extracts unique domains, IPs, and server names, deduplicated via set(). Output can chain directly to intel-skill for OSINT enrichment. Trigger when user asks to analyze a pcap, network capture, traffic dump, extract IOCs from a capture file, or asks what domains/IPs a PCAP contacted."
metadata:
  clawdbot:
    emoji: "📡"
    commands: [analyze, dns, sni, iocs]
    arg_template: "scripts/pcap_analyst.py {command} {args}"
    timeout: 60
    requires:
      bins: [python]
      python_libs: [scapy]
    install:
      - id: pip-scapy
        kind: pip
        packages: [scapy]
        label: "Install scapy for PCAP parsing"
    commands_schema:
      analyze:
        properties:
          path:
            type: string
            description: "Path to .pcap or .pcapng file (max 50MB)"
        required: [path]
      dns:
        properties:
          path:
            type: string
            description: "Path to .pcap or .pcapng file (max 50MB)"
        required: [path]
      sni:
        properties:
          path:
            type: string
            description: "Path to .pcap or .pcapng file (max 50MB)"
        required: [path]
      iocs:
        properties:
          path:
            type: string
            description: "Path to .pcap or .pcapng file (max 50MB)"
          chain:
            type: boolean
            default: false
            description: "Format output as chainable IOC JSON for intel-skill enrichment"
        required: [path]
---

# PCAP Analyst — Streaming network capture IOC extraction

ניתוח קבצי תעבורת רשת (.pcap/.pcapng) בצורה זרימה (streaming) ללא חנק זיכרון.
מחלץ רק עוגנים משמעותיים: שאילתות DNS ו-TLS SNI — ומשרשר אותם ל-intel-skill.

## אילוצי OOM (קריטי)

- **PcapReader בלבד** — אף פעם לא `rdpcap()`. קריאה פקטה-פקטה כ-generator.
- **סינון בשכבת הקריאה** — רק UDP/53 (DNS) + TCP/443 (TLS) עוברים. שאר הפקטות נזרקות.
- **50MB hard gate** — קבצים מעל 50MB נדחים מיד עם הודעה ל-LLM.
- **Dedup ב-set()** — דומיין שמופיע 500 פעמים נספר פעם אחת.

## Quick start

```bash
# ניתוח מלא — DNS queries + answers + TLS SNI במעבר אחד
python {baseDir}/scripts/pcap_analyst.py analyze --path ~/Downloads/capture.pcap

# DNS בלבד — שאילתות + תשובות
python {baseDir}/scripts/pcap_analyst.py dns --path ~/Downloads/capture.pcap

# TLS SNI בלבד — שמות שרתים שהמחשב פנה אליהם
python {baseDir}/scripts/pcap_analyst.py sni --path ~/Downloads/capture.pcap

# חילוץ IOCs + שרשור ל-intel-skill
python {baseDir}/scripts/pcap_analyst.py iocs --path ~/Downloads/capture.pcap --chain
```

## פקודות נתמכות

| פקודה | תיאור | פלט |
|-------|-------|-----|
| `analyze` | סיכום מלא: DNS + TLS SNI | טקסט מפורמט |
| `dns` | שאילתות DNS + תשובות בלבד | טקסט מפורמט |
| `sni` | ערכי TLS SNI בלבד | טקסט מפורמט |
| `iocs` | חילוץ IOCs מאוחד | JSON (עם `--chain` — מבנה ל-intel-skill) |

## שרשור ל-intel-skill

הפלט של `iocs --chain` הוא JSON בפרוטוקול המשותף:
```json
{
  "iocs": {"domains": ["..."], "ips": ["..."], "urls": [], "hashes": []},
  "source": "pcap-analyst",
  "chain_to": "intel-skill",
  "stats": {"raw_domains": 47, "raw_ips": 12, "filtered_domains": 8, "filtered_ips": 5, "selected_total": 13},
  "triage": "📊 Triage Report: Extracted 59 raw IOCs. Filtered out 46 (private/benign). Selected top 13 for analysis."
}
```
העבר את ה-domains/IPs ל-`intel-skill sweep` או `intel-skill cluster` להעשרת OSINT.

## Triage — סינון דטרמיניסטי לפני העשרה

שכבת סינון אוטומטית (`skills/_shared/ioc_triage.py`) פועלת לפני בניית ה-JSON:

1. **Private IPs** — RFC1918 (10.x, 192.168.x, 172.16.x) + loopback + link-local → מוסרים
2. **Benign domains** — שורשי דומיינים לגיטימיים (Microsoft, Google, AWS, Apple, Cloudflare, GitHub, Telegram ועוד ~25) → מוסרים
3. **Top-K Selection** — מקסימום 15 IOCs להעשרה (מיון לפי תדר יורד)

מטרה: מניעת קריסת intel-skill מ-Rate Limit (VT: 4 req/min) ו-Context Bloat ב-LLM.
