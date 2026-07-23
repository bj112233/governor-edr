---
name: persistence-hunter
description: "Windows persistence mechanism scanner. Scans all autorun vectors: Registry Run/RunOnce keys (T1547.001), Startup folders (T1547.004), Scheduled Tasks (T1053.005), and WMI Event Subscriptions (T1546.003). Filters Microsoft-signed noise by default (reduces ~80 legit entries to only suspicious ones). Supports baseline/diff for change detection — save known-good state, then detect new/modified/removed persistence entries. Tags each entry with MITRE ATT&CK technique. Trigger when user asks to check persistence, autorun, startup items, scheduled tasks, registry run keys, WMI subscriptions, or suspects a malware persistence mechanism."
metadata:
  clawdbot:
    emoji: "🔍"
    commands: [scan, baseline, diff]
    arg_template: "scripts/persistence_hunter.py {command} {args}"
    timeout: 45
    requires:
      bins: [python]
    install: []
    commands_schema:
      scan:
        properties:
          include_ms:
            type: boolean
            default: false
            description: "Include Microsoft-signed entries (default: filtered out to reduce noise)"
        required: []
      baseline:
        properties: {}
        required: []
      diff:
        properties:
          include_ms:
            type: boolean
            default: false
            description: "Include Microsoft-signed entries in diff comparison"
        required: []
---

# Persistence Hunter — Windows persistence mechanism scanner

סורק את כל נקודות ה-Autorun ב-Windows לזיהוי מנגנוני הישרדות של נוזקה.
מסנן רעש של Microsoft (כ-80 רשומות לגיטימיות) כדי להציג רק את החשודות.

## וקטורים נסרקים

| וקטור | MITRE | תיאור |
|-------|-------|-------|
| Registry Run/RunOnce | T1547.001 | HKLM + HKCU Run/RunOnce keys |
| Startup folders | T1547.004 | %APPDATA% + %ProgramData% Startup |
| Scheduled Tasks | T1053.005 | כל המשימות המתוזמנות |
| WMI Event Subscription | T1546.003 | __EventConsumer (root\subscription) |

## Quick start

```bash
# סריקה מלאה — רק רשומות לא-Microsoft (ברירת מחדל)
python {baseDir}/scripts/persistence_hunter.py scan

# סריקה כולל Microsoft (ל-audit מלא)
python {baseDir}/scripts/persistence_hunter.py scan --include-ms

# שמירת baseline (known-good state)
python {baseDir}/scripts/persistence_hunter.py baseline

# השוואה מול baseline — רק שינויים
python {baseDir}/scripts/persistence_hunter.py diff
```

## פקודות נתמכות

| פקודה | תיאור | פלט |
|-------|-------|-----|
| `scan` | סריקה מלאה של כל הוקטורים | רשומות מקובצות לפי וקטור |
| `baseline` | שמירת מצב נוכחי כ-known-good | סטטוס + מספר רשומות |
| `diff` | השוואה מול baseline | new/modified/removed |

## זרימת עבודה מומלצת

1. **התקנה נקייה**: `baseline` — שמור את המצב הנקי
2. **חשד לזיהום**: `diff` — הצג רק מה שהשתנה
3. **Audit מלא**: `scan --include-ms` — כלול רשומות Microsoft

## סינון Microsoft

ברירת מחדל: רשומות שמצביעות ל-`C:\Windows\`, `C:\Program Files\`, או בינאריים ידועים של MS
(OneDrive, Edge, Defender, Teams וכו') מסוננות. השתמש ב-`--include-ms` ל-audit מלא.

## תלות

אין תלות חיצונית — משתמש ב-`reg.exe`, `schtasks.exe`, ו-PowerShell (מובנים ב-Windows).
