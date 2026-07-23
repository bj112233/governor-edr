---
name: translator-skill
description: "Translate text between languages via multi-backend fallback (opus-mt → MyMemory → deep-translator → LibreTranslate). All free, no API key. opus-mt is offline (MIT, best Hebrew BLEU) for en↔he; other pairs use online backends. Command 'python', args 'scripts/translator.py --text \"hello\" --to he' or 'scripts/translator.py --file input.txt --to en --output translated.txt'. Auto-detects source language. Trigger when user asks תרגם, translate, תרגום, מה זה אומר באנגלית, etc. NOT for casual conversation — only explicit translation requests."
metadata: {"clawdbot":{"emoji":"🌐","commands":["run"],"arg_template":"scripts/translator.py {args}","requires":{"bins":["python"],"python_libs":["requests","langdetect"]},"install":[{"id":"pip-translator","kind":"pip","packages":["requests","langdetect"],"label":"Translator skill deps"}],"commands_schema":{"run":{"properties":{"text":{"type":"string","description":"Text to translate"},"file":{"type":"string","description":"Path to file to translate"},"stdin":{"type":"boolean","description":"Read text from stdin","default":false},"from":{"type":"string","description":"Source language code (e.g. en, he, fr). Auto-detected if omitted"},"to":{"type":"string","description":"Target language code (e.g. en, he, fr)","default":"he"},"output":{"type":"string","description":"Output file path (for file/stdin translation)"},"backend":{"type":"string","enum":["opus-mt","mymemory","deep-translator","libretranslate"],"description":"Specific backend to use"}}}}}}
---

# Translator Skill

תרגום בין שפות עם זיהוי אוטומטי של שפת המקור ושרשרת fallback חינמית.

## מנועי תרגום (fallback chain)

| מנוע | סדר | מפתח | שפות | הערות |
|------|-----|------|------|-------|
| **opus-mt** | 1 | לא | en↔he | אופליין מלא, MIT, BLEU 40-54, מודלים מ-HuggingFace (~300MB) |
| **MyMemory** | 2 | לא | 50+ | ללא הרשמה, 1000 מילים/יום |
| **deep-translator** | 3 | לא | 130+ | Google Translate web scraper |
| **LibreTranslate** | 4 | לא | 100+ | Self-hosted או instances ציבוריים (נדירים) |

הבוט מנסה opus-mt קודם (en↔he בלבד, אופליין); אם זוג השפות לא נתמך — עובר ל-MyMemory; אם נכשל — deep-translator; אם גם הוא נכשל — LibreTranslate כגיבוי אחרון.

## Quick start

```bash
# תרגום טקסט קצר
python {baseDir}/scripts/translator.py --text "Hello world" --to he
python {baseDir}/scripts/translator.py --text "שלום עולם" --to en

# מ-X ל-Y במפורש
python {baseDir}/scripts/translator.py --text "Bonjour" --from fr --to he

# תרגום קובץ שלם
python {baseDir}/scripts/translator.py --file article.txt --to he --output translated.txt

# תרגום מ-stdin
type input.txt | python {baseDir}/scripts/translator.py --stdin --to en

# בחירת backend ספציפי
python {baseDir}/scripts/translator.py --text "hello" --to he --backend mymemory
python {baseDir}/scripts/translator.py --text "hello" --to he --backend deep-translator

# תרגום קבצים במקביל
python {baseDir}/scripts/translator.py --bulk-dir ./docs --to he --workers 3 --output ./translated

# זיהוי שפה בלבד
python {baseDir}/scripts/translator.py --text "שלום עולם" --detect
```

## שפות נתמכות
auto, en, he, ar, fr, de, es, it, pt, ru, zh-CN, ja, ko, tr ועוד 100+ (תלוי במנוע).

## תרגום מקביל/קבוצתי
- טקסט ארוך (>4500 תווים) מפוצל ל-chunks ומתורגם במקביל (max 3 workers).
- `--bulk-dir` תורגם כל קובץ `.txt` בתיקייה במקביל עם `--workers N`.

## מגבלות
- מגבלת תווים: ~5000 תווים לבקשה (chunks אוטומטיים).
- MyMemory: 1000 מילים/יום אנונימי; deep-translator: לא רשמי, עלול להשתנות.
- LibreTranslate instances ציבוריים עשויים להיות איטיים או חסומים בשעות עומס.
