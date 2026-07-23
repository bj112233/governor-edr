---
name: intel-skill
description: "Threat intelligence enrichment for IPs, domains, file hashes — combines AbuseIPDB, Maltiverse (classification + tags), DNS, WHOIS, ipapi.co (HTTPS geolocation + proxy/VPN/TOR detection), Shodan (ports, CVEs, OS), and VirusTotal (community votes, tags, network) into a unified 0-100 reputation score. Trigger when user asks IOC, reputation, מוניטין, האם IP זדוני, blacklist, threat intel, lookup, whois, dns, domain age, virustotal, abuseipdb, maltiverse, shodan, ip reputation, network osint."
metadata:
  clawdbot:
    emoji: "🛰️"
    commands: [ip, domain, hash, dns, whois, sweep, cluster, israeli, cert, attack, feeds]
    commands_schema:
      ip:
        properties:
          target:
            type: string
            description: "IP address to lookup (IPv4 or IPv6)"
          format:
            type: string
            enum: [markdown, json]
            default: markdown
        required: [target]
      domain:
        properties:
          target:
            type: string
            description: "Domain name (FQDN) to lookup"
          format:
            type: string
            enum: [markdown, json]
            default: markdown
        required: [target]
      hash:
        properties:
          target:
            type: string
            description: "File hash to check (md5, sha1, or sha256)"
          format:
            type: string
            enum: [markdown, json]
            default: markdown
        required: [target]
      dns:
        properties:
          target:
            type: string
            description: "Domain name for DNS lookup (A/AAAA/MX/TXT/NS)"
          format:
            type: string
            enum: [markdown, json]
            default: markdown
        required: [target]
      whois:
        properties:
          target:
            type: string
            description: "Domain or IP for WHOIS/RDAP lookup"
          format:
            type: string
            enum: [markdown, json]
            default: markdown
        required: [target]
      sweep:
        properties:
          threshold:
            type: integer
            default: 10
            description: "Minimum threat score to flag connections (0-100)"
          format:
            type: string
            enum: [markdown, json]
            default: markdown
        required: []
      cluster:
        properties:
          targets:
            type: string
            description: "Comma-separated IOCs (IPs, domains, hashes) to cluster"
          threshold:
            type: number
            default: 0.80
            description: "Cosine similarity threshold for clustering (0.0-1.0)"
          format:
            type: string
            enum: [markdown, json]
            default: markdown
        required: [targets]
      israeli:
        properties:
          target:
            type: string
            description: "IP address or domain for Israeli-specific monitoring"
          format:
            type: string
            enum: [markdown, json]
            default: markdown
        required: [target]
      cert:
        properties:
          format:
            type: string
            enum: [markdown, json]
            default: markdown
        required: []
      attack:
        properties:
          technique:
            type: string
            description: "MITRE ATT&CK technique ID (e.g. T1059, T1071, T1090)"
          format:
            type: string
            enum: [markdown, json]
            default: json
        required: [technique]
      feeds:
        properties:
          source:
            type: string
            enum: [urlhaus, threatfox, all]
            description: "Threat feed source (URLhaus malicious URLs, ThreatFox botnet C2 IOCs)"
          limit:
            type: integer
            default: 50
            description: "Max IOCs to display"
          format:
            type: string
            enum: [markdown, json]
            default: markdown
        required: [source]
    arg_template: "scripts/intel.py {command} {args}"
    requires:
      bins: [python]
    install: []
---

# Intel Skill — IOC reputation & enrichment

מאחדת מספר מקורות אינטליגנציית-איומים חינמיים לפעולת lookup יחידה. בלי API keys התוצאות חלקיות אך שימושיות; עם keys מקבלים תמונה מלאה.

## Quick start
```bash
# Reputation לכתובת IP (AbuseIPDB + reverse DNS)
python {baseDir}/scripts/intel.py ip --target 8.8.8.8

# Reputation לדומיין (Maltiverse + VT + RDAP)
python {baseDir}/scripts/intel.py domain --target example.com

# בדיקת hash זדוני (Maltiverse + VT)
python {baseDir}/scripts/intel.py hash --target <sha256>

# Pure DNS lookup (A / AAAA / MX / TXT / NS)
python {baseDir}/scripts/intel.py dns --target example.com

# WHOIS-lite (RDAP-based, ללא תלות חיצונית)
python {baseDir}/scripts/intel.py whois --target example.com

# Semantic clustering of multiple IOCs (embeddings via local LLM)
python {baseDir}/scripts/intel.py cluster --targets "8.8.8.8,1.1.1.1,example.com" --threshold 0.80

# Local network sweep — סורק חיבורים פעילים (Triage: light → deep)
python {baseDir}/scripts/intel.py sweep [--threshold 10]

# מעקב ישראלי משודרג
python {baseDir}/scripts/intel.py israeli --target <ip|domain>

# CERT-IL feed
python {baseDir}/scripts/intel.py cert

# MITRE ATT&CK technique lookup
python {baseDir}/scripts/intel.py attack --technique T1059

# Live threat feeds (URLhaus + ThreatFox)
python {baseDir}/scripts/intel.py feeds --source urlhaus --limit 50
python {baseDir}/scripts/intel.py feeds --source threatfox
python {baseDir}/scripts/intel.py feeds --source all
```

## Environment variables
| Var | תפקיד | חובה? |
|---|---|---|
| `ABUSEIPDB_API_KEY` | מפתח AbuseIPDB (חינמי, 1000 lookups/day) | מומלץ ל-`ip` |
| `VIRUSTOTAL_API_KEY` | מפתח VirusTotal (4 lookups/min בחינמי) | אופציונלי |
| `SHODAN_API_KEY` | מפתח Shodan (100 credits/month free) | אופציונלי |

## Output
- ניקוד מאוחד 0-100 (0 נקי, 100 ודאי-זדוני) — משוקלל מכלל המקורות.
- **IP report**: AbuseIPDB confidence, Maltiverse classification + tags + blacklist count, VirusTotal stats + community votes + tags + network, ipapi.co (geolocation, proxy/VPN/TOR/hosting flags), Shodan (open ports, CVEs, OS, ASN, org).
- **Domain report**: Maltiverse, VT, RDAP/WHOIS, DNS records, domain age heuristics.
- **Hash report**: Maltiverse classification + score + tags, VT file analysis.
- **Sweep report**: סורק חיבורים פעילים (ESTABLISHED) ומריץ Triage funnel — light sweep (Maltiverse + ipapi.co) על כל ה-IPים, ו-deep enrichment (VT + Shodan) רק על חשודים. מדווח רק IPים מעל threshold.
- JSON זמין דרך `--format json`.

## Fallback Commands

If a command fails (e.g. due to network timeout or missing API key), the agent will try these safer alternatives automatically:

| Original | Fallback | Why |
|---|---|---|
| `sweep` | `sweep` (no args) | Removes optional `--threshold` that may cause timeout |
| `ip` | `ip` (no `--target`) | Falls back to local IP triage if target is invalid |
| `domain` | `domain` (no `--target`) | Falls back to default domain analysis |

## אינטגרציה עם Sentinel
`monitor_engine` יכול לקרוא ל-`intel ip --target <ip>` *לפני* `block_ip`, להפוך החלטות-חסימה למבוססות-אינטל ולא רק יוריסטיות.
