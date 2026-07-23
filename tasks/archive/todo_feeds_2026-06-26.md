# Sprint: Live Threat Feeds — Abuse.ch (URLhaus + ThreatFox)

## יעד
הפיכת Sentinel ממערכת תגובתית למערכת מניעתית — משיכת IOCs חיים מ-Abuse.ch
(URLhaus: malicious URLs, ThreatFox: botnet C2/malware IOCs) והזנה ל-Threat Scoring.

## אילוצי API (נכון ל-2026)
- **URLhaus**: דורש Auth-Key (חינמי, https://auth.abuse.ch/). נקודת CSV:
  `https://urlhaus-api.abuse.ch/v2/files/exports/{KEY}/recent.csv`
  נקודה חלופית ללא מפתח (legacy, עובדת לעיתים):
  `https://urlhaus.abuse.ch/downloads/csv_online/`
- **ThreatFox**: דורש Auth-Key ב-header. POST:
  `https://threatfox-api.abuse.ch/api/v1/` עם `{"query":"get_iocs","days":1}`
- **אסטרטגיית נפילה**: אם אין מפתח → נסה legacy CSV → אם נכשל → החזר רשימה ריקה
  + הודעת אזהרה. לעולם אל תקריס את ה-enrichment.

## עקרונות עיצוב
- **דפוס CERT-IL**: אותו מבנה כמו `cert_il_feed.py` — fetcher + parser + cache
- **Skill-level**: הכל ב-`skills/intel-skill/scripts/` (כבד import-linter)
- **Cache 24h**: שמירת תוצאות ב-`_CACHE_DIR` כדי לא להכביד על API
- **IOC extraction**: שימוש ב-`skill_ioc_extractor` הקיים
- **Threat Scoring integration**: IOCs מ-Abuse.ch מקבלים score boost ב-orchestrator

## 1. URLhaus Fetcher — `urlhaus_feed.py` (חדש)
- [ ] `fetch_urlhaus_csv(limit=100) -> list[dict]`
  - קריאת CSV מ-URLhaus (Auth-Key מ-env `URLHAUS_AUTH_KEY`, fallback ל-legacy)
  - פרסור שורות: id, dateadded, url, url_status, threat, tags, urlhaus_link, reporter
  - סינון: רק `url_status == "online"` + `threat` לא ריק
  - הגבלת `limit` שורות (ברירת מחדל 100)
  - Cache 24h ב-`_CACHE_DIR/urlhaus.json`
- [ ] `extract_urlhaus_iocs(rows: list[dict]) -> dict`
  - הפעלת `skill_ioc_extractor.extract_iocs` על url + threat + tags
  - החזרת `{urls, domains, ips, hashes}` דה-דופליקציה

## 2. ThreatFox Fetcher — `threatfox_feed.py` (חדש)
- [ ] `fetch_threatfox_iocs(days=1) -> list[dict]`
  - POST ל-ThreatFox API (Auth-Key מ-env `THREATFOX_AUTH_KEY`)
  - פרסור `data[]`: id, ioc, threat_type, ioc_type, malware, confidence_level, first_seen, tags
  - סינון: `confidence_level >= 50` (רק בינוני+)
  - Cache 24h ב-`_CACHE_DIR/threatfox.json`
- [ ] `extract_threatfox_iocs(rows: list[dict]) -> dict`
  - מיפוי `ioc_type` לסוג IOC (ip/domain/url/sha256)
  - החזרת `{urls, domains, ips, hashes, malware_map}` כאשר `malware_map`
    מקשר כל IOC לשם ה-malware (לשימוש ב-MITRE mapping)

## 3. אינטגרציה ל-Orchestrator — `orchestrator.py` (שינוי)
- [ ] `analyze_ip`: בדיקה האם IP מופיע ב-ThreatFox/URLhaus → score boost +20
- [ ] `analyze_domain`: כנ"ל
- [ ] `analyze_hash`: כנ"ל (ThreatFox בלבד — URLhaus לא כולל hashes)
- [ ] הוספת `threat_feeds` dict ל-payload: `{urlhaus: bool, threatfox: bool, malware: str|None}`

## 4. פקודה חדשה `cmd_feeds` — `intel_commands.py` + `intel_facade.py`
- [ ] `cmd_feeds(source, fmt)` — הצגת IOCs חיים מ-URLhaus/ThreatFox
  - `source`: "urlhaus" | "threatfox" | "all"
  - Markdown: טבלת IOCs + malware family + threat type
  - JSON: רשימה מלאה
- [ ] subparser `feeds --source urlhaus --limit 50` ב-`intel_facade.py:main()`
- [ ] עדכון `SKILL.md` עם הפקודה החדשה

## 5. MITRE Mapping Enhancement — `mitre_mapping.py` (שינוי)
- [x] מיפוי `threat_type` מ-ThreatFox ל-MITRE (THREAT_TYPE_MITRE_MAP)
- [x] `malware` name → TAG_MAP lookup
- [x] URLhaus match → T1566 signal, ThreatFox match → T1071 signal

## 6. טסטים — `tests/test_abuse_feeds.py` (חדש)
- [x] 23 טסטים: URLhaus CSV, ThreatFox JSON, IOC extraction, cache, error fallback,
  threat_feeds_check, MITRE mapping, cmd_feeds rendering
- [x] lint-gate עובר

## Review

### סיכום ביצוע
6 items הושלמו. ALL GATES PASSED. 23 טסטים חדשים.

### קבצים שנוצרו (3)
| קובץ | שורות | תפקיד |
|---|---|---|
| `skills/intel-skill/scripts/urlhaus_feed.py` | 96 | CSV fetcher + IOC extraction + 24h cache |
| `skills/intel-skill/scripts/threatfox_feed.py` | 130 | JSON fetcher + confidence filter + malware_map |
| `skills/intel-skill/scripts/threat_feeds_check.py` | 94 | Cross-feed target lookup (never crashes) |

### קבצים ששונו (5)
| קובץ | שינוי |
|---|---|
| `skills/intel-skill/scripts/orchestrator.py` | 3x check_target_in_feeds + score boost +20 |
| `skills/intel-skill/scripts/osint_gatherer.py` | urlhaus_feed + threatfox_feed re-export |
| `skills/intel-skill/scripts/intel_commands.py` | cmd_feeds + _render_feed helper |
| `skills/intel-skill/scripts/intel_facade.py` | feeds subparser + dispatch |
| `skills/intel-skill/scripts/intel.py` | cmd_feeds re-export |
| `skills/intel-skill/scripts/mitre_mapping.py` | threat_feeds → MITRE signals |
| `skills/intel-skill/SKILL.md` | feeds command schema + usage |

### החלטות עיצוב
1. **Graceful Degradation**: אם אין Auth-Key → legacy CSV (URLhaus) / rate-limited
   request (ThreatFox) → אם נכשל → רשימה ריקה. לעולם לא מקריס enrichment.
2. **Score boost +20**: כש-target מופיע ב-feed, score עולה ב-20 (capped 100).
   זה הופך IOCs חיים ל"זדוני סביר" גם אם VT/Maltiverse לא מכירים בהם עדיין.
3. **THREAT_TYPE_MITRE_MAP**: botnet_cc→T1071, payload_delivery→T1566,
   malware_artefact→T1055. מיפוי דטרמיניסטי, לא LLM.
4. **malware_map**: כל IOC מ-ThreatFox מקושר ל-malware family — מאפשר MITRE
   enrichment עתידי לפי שם ה-malware (לא רק threat_type).
5. **threat_feeds_check**: מודול נפרד שעוטף את שני ה-feeds ב-try/except מלא.
   לעולם לא מקריס את ה-orchestrator גם אם שני ה-APIs נופלים.

### השפעה מבצעית
Sentinel עבר מ"תגובתי" ל"מניעתי": כעת הוא מכיר IOCs חיים מ-Abuse.ch
לפני שהם מגיעים לרשת המקומית. דוחות כוללים "Target found in ThreatFox"
+ malware family + MITRE technique — לא רק "כתובת זדונית 85/100".

