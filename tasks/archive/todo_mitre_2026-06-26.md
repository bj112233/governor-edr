# Sprint: MITRE ATT&CK Mapping (P1)

## יעד
הפיכת דוחות Sentinel מ"רשימת כתובות רעות" ל"דו"ח מודיעין תקיפה" — מיפוי
ממצאי enrichment לטכניקות MITRE ATT&CK (T1059, T1071, T1090, וכו').

## עקרונות עיצוב
- **Pure data + pure logic**: בסיס נתונים סטטי (ללא I/O) + פונקציית מיפוי דטרמיניסטית
- **Signal-based mapping**: לא ניחוש מ-CVE בלבד — מיפוי מבוסס אינדיקטורים מוחשיים
  (פורטים, דגלי proxy/TOR, תגיות Maltiverse/VT, classification)
- **Confidence scoring**: כל טכניקה מקבלת confidence 0.0-1.0 לפי מספר האיתותים התומכים
- **Skill-level**: כל הקוד ב-`skills/intel-skill/scripts/` (כבד import-linter)

## 1. MITRE ATT&CK Database — `mitre_attack_db.py` (חדש)
בסיס נתונים סטטי, pure stdlib, אפס תלות חיצונית.

- [x] טבלת טכניקות: `TECHNIQUES: dict[str, Technique]` — 13 טכניקות
- [x] טבלת מיפוי איתותים: `PORT_MAP`, `TAG_MAP`
- [x] טבלת CVE ידועות: `CVE_TECHNIQUE_MAP` — 6 CVEs נפוצות

## 2. MITRE Mapping Engine — `mitre_mapping.py` (חדש)
פונקציית מיפוי דטרמיניסטית. Pure logic, no I/O.

- [x] `map_payload_to_mitre(payload: dict) -> list[MitreMatch]`
- [x] `map_cves_to_mitre(cves: list[str]) -> list[MitreMatch]`
- [x] `lookup_technique(technique_id: str) -> Technique | None`

## 3. אינטגרציה ל-Orchestrator — `orchestrator.py` (שינוי)
- [x] `analyze_ip`: `mitre_techniques` ב-payload
- [x] `analyze_domain`: כנ"ל
- [x] `analyze_hash`: כנ"ל

## 4. Rendering — `renderer.py` (שינוי)
- [x] סעיף "## 🎯 MITRE ATT&CK Mapping" עם confidence bar + signals

## 5. פקודה חדשה `cmd_attack` — `intel_commands.py` + `intel_facade.py`
- [x] `cmd_attack(technique_id, fmt)` — lookup + reverse signal mapping
- [x] subparser `attack --technique T1059` ב-`intel_facade.py:main()`
- [x] `SKILL.md` עודכן עם schema + usage

## 6. טסטים — `tests/test_mitre_mapping.py` (חדש)
- [x] 34 טסטים: DB, IP/domain/hash mapping, CVE, confidence, cmd_attack, renderer
- [x] lint-gate עובר

## Review

### סיכום ביצוע
6 items הושלמו. ALL GATES PASSED. 34 טסטים חדשים.

### קבצים שנוצרו (2)
| קובץ | שורות | תפקיד |
|---|---|---|
| `skills/intel-skill/scripts/mitre_attack_db.py` | 122 | 13 טכניקות + PORT_MAP + TAG_MAP + CVE_TECHNIQUE_MAP |
| `skills/intel-skill/scripts/mitre_mapping.py` | 182 | map_payload_to_mitre + map_cves_to_mitre + lookup_technique |

### קבצים ששונו (5)
| קובץ | שינוי |
|---|---|
| `skills/intel-skill/scripts/orchestrator.py` | 3x map_payload_to_mitre injection |
| `skills/intel-skill/scripts/renderer.py` | MITRE section עם confidence bar |
| `skills/intel-skill/scripts/intel_commands.py` | cmd_attack (lookup + reverse signals) |
| `skills/intel-skill/scripts/intel_facade.py` | attack subparser + dispatch |
| `skills/intel-skill/scripts/intel.py` | cmd_attack re-export |
| `skills/intel-skill/SKILL.md` | attack command schema + usage |

### החלטות עיצוב
1. **Pure data + pure logic**: בסיס נתונים סטטי (O(1) lookups) + מנוע מיפוי
   דטרמיניסטי. אפס קריאות API, אפס latency, אפס hallucination surface.
2. **Signal-based mapping**: מיפוי מבוסס אינדיקטורים מוחשיים (פורטים, דגלי
   proxy/TOR, תגיות Maltiverse/VT, classification, domain age, CVEs).
3. **Confidence scoring**: `signals_matched / max_signals` — שקוף וניתן לבדיקה.
4. **Payload-adapted**: מנוע מותאם למבנה ה-payload האמיתי של ה-orchestrator
   (sources.shodan.ports, sources.ipapi_co.proxy, sources.rdap.registered).

### טכניקות מכוסות (13)
T1059, T1071, T1090, T1090.003, T1021.001, T1021.002, T1021.004,
T1048, T1566, T1190, T1055, T1496, T1046

