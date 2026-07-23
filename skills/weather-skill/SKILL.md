---
name: weather-skill
description: "Live weather forecast in Hebrew via Open-Meteo (free, no API key). Command 'python', args 'scripts/weather.py --location <city_he_or_en>' or 'scripts/weather.py --lat X --lon Y'. Default location is Tel Aviv. Returns current temp + 7-day forecast in Hebrew. Trigger when user asks מזג אוויר, תחזית, weather, forecast, ירידה גשם, חם/קר, temperature, humidity. Always fetch live — never answer from memory."
metadata: {"clawdbot":{"emoji":"🌤️","commands":["run"],"arg_template":"scripts/weather.py {args}","requires":{"bins":["python"],"python_libs":["requests"]},"install":[{"id":"pip-weather","kind":"pip","packages":["requests"],"label":"Weather skill deps"}],"commands_schema":{"run":{"properties":{"location":{"type":"string","description":"City name in Hebrew or English (e.g. תל אביב, New York). Default: Tel Aviv"},"lat":{"type":"number","description":"Latitude (alternative to location)"},"lon":{"type":"number","description":"Longitude (alternative to location)"},"format":{"type":"string","enum":["markdown","json"],"default":"markdown"},"air_quality":{"type":"boolean","description":"Include air quality report","default":false}}}}}}
---

# Weather Skill

תחזית מזג אוויר חיה בעברית. משתמש ב־Open-Meteo (חינמי, ללא API key) + Nominatim ל־geocoding.

## Quick start

```bash
# תחזית לתל אביב (ברירת מחדל)
python {baseDir}/scripts/weather.py

# עיר אחרת
python {baseDir}/scripts/weather.py --location "ירושלים"
python {baseDir}/scripts/weather.py --location "New York"

# לפי קואורדינטות
python {baseDir}/scripts/weather.py --lat 31.78 --lon 35.22

# פלט JSON
python {baseDir}/scripts/weather.py --location "חיפה" --format json

# דוח איכות אוויר
python {baseDir}/scripts/weather.py --location "תל אביב" --air-quality

# התראות על ספים (גשם >10מ"מ, רוח >50 קמ"ש, טמפ <5°C, UV >8)
python {baseDir}/scripts/weather.py --location "חיפה" --alert-on "rain>10,wind>50,temp<5"
```

## Output (Markdown)
- מיקום מזוהה + תאריך
- מזג אוויר נוכחי: טמפרטורה, תחושה, לחות, רוח, גשם
- תחזית 7 ימים: max/min/precipitation לכל יום
