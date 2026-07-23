---
name: geocode-skill
description: "Address ↔ coordinates + distance + traffic-aware routing. Uses Nominatim (OSM, free) + HERE API (30K/month free tier, includes real-time traffic). Commands: 'scripts/geocode.py forward --address \"רחוב הרצל 1, תל אביב\"', 'scripts/geocode.py reverse --lat 32.08 --lon 34.78', 'scripts/geocode.py distance --from \"תל אביב\" --to \"חיפה\"', 'scripts/geocode.py route --from \"ראש העין\" --to \"חיפה\"'. Trigger: קואורדינטות, כתובת, מרחק, זמן נסיעה, עומסים, GPS, traffic."
metadata: {"clawdbot":{"emoji":"📍","commands":["forward","reverse","distance","bbox","route","alternative"],"arg_template":"scripts/geocode.py {command} {args}","requires":{"bins":["python"],"python_libs":["requests"]},"env_vars":[{"name":"HERE_API_KEY","optional":true,"description":"HERE API key for traffic data"},{"name":"HERE_MONTHLY_CAP","optional":true,"default":"25000","description":"Monthly API call cap (safety margin under 30K free tier)"}],"commands_schema":{"forward":{"properties":{"address":{"type":"string","description":"Address to geocode (e.g. \"רחוב הרצל 1, תל אביב\")"}},"required":["address"]},"reverse":{"properties":{"lat":{"type":"number","description":"Latitude"},"lon":{"type":"number","description":"Longitude"}},"required":["lat","lon"]},"distance":{"properties":{"from":{"type":"string","description":"Starting location name"},"to":{"type":"string","description":"Destination location name"},"from_lat":{"type":"number","description":"Starting latitude (alternative to from)"},"from_lon":{"type":"number","description":"Starting longitude (alternative to from)"},"to_lat":{"type":"number","description":"Destination latitude (alternative to to)"},"to_lon":{"type":"number","description":"Destination longitude (alternative to to)"}}},"bbox":{"properties":{"address":{"type":"string","description":"Address to get bounding box for"}},"required":["address"]},"route":{"properties":{"from":{"type":"string","description":"Starting location name"},"to":{"type":"string","description":"Destination location name"},"from_lat":{"type":"number","description":"Starting latitude (alternative to from)"},"from_lon":{"type":"number","description":"Starting longitude (alternative to from)"},"to_lat":{"type":"number","description":"Destination latitude (alternative to to)"},"to_lon":{"type":"number","description":"Destination longitude (alternative to to)"},"waypoint":{"type":"string","description":"Intermediate waypoint (repeatable)"},"alternatives":{"type":"integer","description":"Number of alternative routes","default":1}}},"alternative":{"properties":{},"description":"Get alternative routes for previous route query"}}}}
---

# Geocode Skill

המרת כתובות ↔ קואורדינטות + חישוב מרחקים + **מסלולים עם עומסים בזמן אמת**. משתמש ב:
- **Nominatim** (OpenStreetMap) — חינמי, ללא API key
- **HERE API** — 30,000 בקשות/חודש חינם, כולל traffic data

⚠️ **אזהרת עלות**: מעבר ל-30K = ~$1 לכל 1,000 קריאות. נדרש כרטיס אשראי בהרשמה.

## Quick start

```bash
# כתובת → קואורדינטות (forward)
python {baseDir}/scripts/geocode.py forward --address "רחוב הרצל 1, תל אביב"
python {baseDir}/scripts/geocode.py forward --address "Eiffel Tower, Paris"

# קואורדינטות → כתובת (reverse)
python {baseDir}/scripts/geocode.py reverse --lat 32.0853 --lon 34.7818

# מרחק בין שתי נקודות (קו אווירי)
python {baseDir}/scripts/geocode.py distance --from "תל אביב" --to "חיפה"
python {baseDir}/scripts/geocode.py distance --from-lat 32.08 --from-lon 34.78 --to-lat 32.79 --to-lon 34.99

# מסלול נסיעה עם עומסים בזמן אמת (HERE Traffic)
python {baseDir}/scripts/geocode.py route --from "ראש העין" --to "חיפה"
python {baseDir}/scripts/geocode.py route --from-lat 32.08 --from-lon 34.78 --to-lat 32.79 --to-lon 34.99

# מסלול עם עצירות ביניים (waypoints) — דורש HERE API
python {baseDir}/scripts/geocode.py route --from "תל אביב" --to "חיפה" --waypoint "נתניה" --waypoint "חדרה"

# מסלול עם חלופות (alternative routes)
python {baseDir}/scripts/geocode.py route --from "תל אביב" --to "חיפה" --alternatives 2

# מסלול חלופי ללא צורך לציין כתובות שוב
python {baseDir}/scripts/geocode.py alternative

# מסלול עם פירוט מקטעים (annotations — OSRM mode)
python {baseDir}/scripts/geocode.py route --from "תל אביב" --to "חיפה" --annotations
```

## יכולות

| פקודה | תיאור | מקור נתונים |
|-------|-------|-------------|
| `forward` | כתובת → קואורדינטות | Nominatim (OSM) / HERE — **LRU cache בזיכרון בלבד** |
| `reverse` | קואורדינטות → כתובת | Nominatim |
| `distance` | מרחק קו אווירי (haversine) | חישוב לוקאלי |
| `route` | מסלול + עומסים + עצירות ביניים | **HERE Traffic** → OSRM → Haversine |
| `alternative` | מסלול חלופי (זוכר כתובות אחרונות) | HERE Traffic |

## Routing Chain (Priority)

```
HERE Traffic API → OSRM → Haversine (fallback)
```

| תוצאה | תנאי | מה מוחזר |
|-------|------|----------|
| **HERE Traffic** | HERE_API_KEY set + success | זמן נסיעה אמיתי + עומסים/תקלות |
| **OSRM** | HERE נכשל/חסר API key | זמן נסיעה מחושב (ללא traffic) |
| **Haversine** | שניהם נכשלים | מרחק קו אווירי + הערכה @ 60 קמ/ש |

### route command
- **HERE Traffic**: מנסה ראשון אם HERE_API_KEY מוגדר
- **OSRM**: fallback אם HERE לא זמין
- **Haversine**: תמיד עובד כ-reserve
- **--annotations**: פירוט מקטעים עם מהירויות (OSRM mode)

### distance vs route
| פקודה | מה מחושב | מתי להשתמש |
|-------|----------|------------|
| `distance` | מרחק קו אווירי (great-circle) | מרחק בין 2 נקודות בלי routing |
| `route` | מרחק דרכים + זמן נסיעה אמיתי | נסיעה בפועל — חושב אותו כמו Waze |

## יכולות נוספות — Waypoints & מסלולים

| תכונה | תיאור | דוגמה |
|-------|-------|-------|
| **Waypoints** | עצירות ביניים במסלול | `route --from TLV --to Haifa --waypoint "נתניה"` |
| **Alternatives** | מסלולים חלופיים | `route --from TLV --to Haifa --alternatives 2` |
| **Polyline** | נתוני מסלול לציור מפה | מוחזר ב-API, דורש פענוח |

### מפת מסלול (Map Visualization)

**HERE API מחזירה polyline** — נתונים לציור המסלול על מפה:
- **שימוש**: קישור ל-OpenStreetMap / Leaflet / Google Maps
- **דוגמה**: https://www.openstreetmap.org/directions?engine=fossgis_osrm_car&route=32.0853%2C34.7818%3B32.7940%2C34.9896

**אפשרויות צפייה במפה:**
1. **OpenStreetMap Directions**: הזנת נקודות ידנית
2. **Google Maps**: קישור ישיר עם קואורדינטות
3. **HERE WeGo**: הצגת המסלול המדויק (חינם)

## הערות API

| שירות | מגבלה | סטטוס |
|-------|-------|-------|
| Nominatim | 1 req/sec | חינם לנצח |
| **HERE Routing Car** | **30K req/month** | ✅ בשימוש |
| **HERE Geocode** | **30K req/month** | ✅ בשימוש מועט |
| HERE Time-Aware Routing | **5K req/month** | ❌ לא בשימוש (ללא `departureTime`) |
| HERE Traffic API | **5K req/month** | ❌ לא בשימוש (נפרד מהרוטינג) |
| OSRM | Public demo | חינם, rate limited |

### ⚠️ אזהרות HERE Base Plan

**אסור לשימוש חינמי:**
- ❌ **Permanent Geocoding** — אחסון תוצאות geocode בדיסק (אנחנו משתמשים ב-LRU בזיכרון בלבד)
- ❌ **Time-Aware Routing** — routing עם `departureTime=now` (מוגבל ל-5K/חודש)
- ❌ **Traffic API נפרד** — קריאות ישירות ל-`/traffic` (מוגבל ל-5K/חודש)

**מה מותר:**
- ✅ **Routing Car** — מסלול רכב בסיסי (30K/חודש)
- ✅ **travelSummary ב-return** — מחזיר traffic data כחלק מרוטינג רגיל
- ✅ **Geocode + Reverse Geocode** — 30K/חודש (אנחנו מעדיפים Nominatism)

### הגנות עלות מובנות (Cost Guards)

| מנגנון | הגדרה | מטרה |
|--------|-------|------|
| `_HERE_MONTHLY_CAP` | 25,000 (default) | Safety margin מתחת ל-30K |
| `_here_rate_limit()` | קאונטר בסשן | עצירה אוטומטית לפני חריגה |
| LRU Cache | 256 items | מניעת קריאות כפולות בתוך סשן |
| **Route Context** | `route_context.json` | זיכרון מסלול אחרון בלבד (לא geocoding) |

**HERE API Key**: נשמר בקוד, ניתן לדרוס דרך משתנה סביבה `HERE_API_KEY`

### המלצות למניעת חיובים

1. **LRU Cache בלבד**: Geocoding results נשמרים רק בזיכרון (256 items) — לא בדיסק, לפי תנאי HERE
2. **Route Context**: רק מסלול אחרון נשמר בדיסק לפקודת `alternative`
3. **Rate limiting**: הגבל כל משתמש קצה — לא לתת למשתמש יחיד לגמור את המכסה
4. **Monthly Cap**: הגדר `HERE_MONTHLY_CAP=20000` אם אתה רוצה safety margin גדול יותר
