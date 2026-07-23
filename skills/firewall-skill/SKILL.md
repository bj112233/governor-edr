---
name: firewall-skill
description: "Windows Firewall management — block / unblock IPs and ports, list active blocks, query drop events from pfirewall.log, and aggregate stats. Wraps `netsh advfirewall`. Trigger when user asks חסום, חסימה, block, unblock, שחרור, חומת אש, firewall, drops, drop events, blocked IPs, list rules, חסום פורט, block port. Replaces the legacy block_ip / unblock_ip / get_firewall_drops tools with a single skill."
metadata: {"clawdbot":{"emoji":"🔥","commands":["block","unblock","list","drops","stats","block-cidr","block-port","unblock-port","whitelist","audit","sweep"],"arg_template":"scripts/firewall.py {command} {args}","requires":{"bins":["python","netsh"]},"install":[],"commands_schema":{"block":{"properties":{"ip":{"type":"string","description":"IP address to block"},"duration":{"type":"string","description":"Auto-unblock duration (e.g. 30s, 15m, 24h, 7d)"},"reason":{"type":"string","description":"Reason for blocking"}},"required":["ip"]},"unblock":{"properties":{"ip":{"type":"string","description":"IP address to unblock"}},"required":["ip"]},"block-cidr":{"properties":{"network":{"type":"string","description":"CIDR range (e.g. 10.0.0.0/24)"},"reason":{"type":"string"}},"required":["network"]},"block-port":{"properties":{"port":{"type":"integer","description":"Port number (1-65535)"},"protocol":{"type":"string","enum":["TCP","UDP"],"default":"TCP"},"reason":{"type":"string"}},"required":["port"]},"unblock-port":{"properties":{"port":{"type":"integer","description":"Port number to unblock"},"protocol":{"type":"string","enum":["TCP","UDP"],"default":"TCP"}},"required":["port"]},"list":{"properties":{}},"stats":{"properties":{}},"drops":{"properties":{"count":{"type":"integer","default":20}}},"sweep":{"properties":{}},"audit":{"properties":{"count":{"type":"integer","default":20}}},"whitelist":{"properties":{"action":{"type":"string","enum":["list","add","remove"]},"ip":{"type":"string"}},"required":["action"]}}}}
---

# Firewall Skill

ניהול חומת האש של Windows — חסימה, שחרור, תצוגה ואגרגציה של אירועי DROP.

## Quick start

```bash
# בחירת backend (ברירת מחדל: netsh; מומלץ: powershell ב-Windows 8+/2012+)
python {baseDir}/scripts/firewall.py --backend powershell list

# חסימת כתובת IP (יוצר rule SENTINEL_BLOCK_<ip> בכיוונים in+out)
python {baseDir}/scripts/firewall.py block --ip 1.2.3.4
python {baseDir}/scripts/firewall.py block --ip 1.2.3.4 --duration 24h --reason "Brute force"

# שחרור חסימה
python {baseDir}/scripts/firewall.py unblock --ip 1.2.3.4

# חסימת טווח CIDR (רשת שלמה)
python {baseDir}/scripts/firewall.py block-cidr --network 10.0.0.0/24 --reason "VPN range"

# חסימת פורט (inbound + outbound)
python {baseDir}/scripts/firewall.py block-port --port 8080 --protocol TCP --reason "Suspicious service"
python {baseDir}/scripts/firewall.py block-port --port 53 --protocol UDP

# שחרור פורט
python {baseDir}/scripts/firewall.py unblock-port --port 8080 --protocol TCP

# Whitelist ניהול — IP/CIDR שאינם ניתנים לחסימה
python {baseDir}/scripts/firewall.py whitelist --action list
python {baseDir}/scripts/firewall.py whitelist --action add --ip 192.168.1.1
python {baseDir}/scripts/firewall.py whitelist --action remove --ip 192.168.1.1

# רשימת כל ה-Sentinel blocks הפעילים
python {baseDir}/scripts/firewall.py list

# 20 אירועי DROP אחרונים מ-pfirewall.log
python {baseDir}/scripts/firewall.py drops --count 20

# סטטיסטיקה: כמה rules פעילים, מתי block אחרון, רמת פעילות
python {baseDir}/scripts/firewall.py stats

# Audit log — היסטוריית פעולות
python {baseDir}/scripts/firewall.py audit --count 50

# Sweep — ניקוי חסימות שפג תוקפן (duration)
python {baseDir}/scripts/firewall.py sweep
```

## Output
- `block` / `unblock` — שורת סטטוס ✅/❌.
- `list` — טבלת `IP | direction | action | rule_name`.
- `drops` — לוג אירועי DROP מובנה.
- `stats` — מונים + timestamp של האירוע האחרון.

## Fallback Commands

If a command fails (e.g. missing admin rights or log not enabled), the agent will try these safer alternatives automatically:

| Original | Fallback | Why |
|---|---|---|
| `list` | `stats` | `stats` does not enumerate rules, only counts — no admin required |
| `stats` | `drops` | `drops` reads log file instead of querying firewall state |

## הערות
- כל החוקים נוצרים בשם `SENTINEL_BLOCK_<ip>` כדי שיהיו ניתנים לזיהוי וניקוי.
- דורש הרשאות אדמין כדי להפעיל `netsh advfirewall` או PowerShell NetSecurity.
- `--backend powershell` משתמש במודול `NetSecurity` המובנה (Windows 8+ / Server 2012+).
- `drops` קורא מ-`C:\Windows\System32\LogFiles\Firewall\pfirewall.log` → דורש שלוג חומת האש מאופשר.
