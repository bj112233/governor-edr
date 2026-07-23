---
name: release-hygiene
description: צ'קליסט לפני קומיט קונפיג, יצירת ZIP, פרסום, או שיתוף קבצים עם גורם חיצוני
allowed-tools:
  - read
  - grep
  - glob
  - exec
triggers:
  - user
  - model
---

# Release Hygiene — צ'קליסט לפני שחרור/שיתוף

> **מתי להריץ:** לפני כל קומיט של קונפיג, יצירת ZIP, פרסום ל-remote, או שיתוף קבצים עם גורם חיצוני.
> **כלל:** FAIL אחד = עצירה מיידית ודיווח למשתמש. אל תמשיך, אל תעקוף.

---

## רשימת "לעולם לא לשתף"

קבצים שאסור להעלות לשרת/ענן/remote או לשתף עם גורם חיצוני. מחיקה — רק באישור מפורש.

| קובץ | מיקום | סיבה |
|------|------|------|
| `tactical_bot_git_backup_20260723_140422.zip` | מחוץ לעץ (ספריית האב) | מלוא ההיסטוריה הישנה (1049 קומיטים) עם PII: MACs, chat_id, שמות, נתיבים. גיבוי מקומי בלבד. |
| `.env` | שורש הפרויקט | מפתחות API אמיתיים (VirusTotal, AbuseIPDB, Telegram bot token). |
| `config/trusted_devices.json` | `config/` | כתובות MAC אמיתיות של הרשת הביתית. |
| `config/news_feeds.json` | `config/` | chat_id אמיתי ב-delivery.telegram. |
| `config/channels.json` | `config/` | chat_id אמיתי ב-allow_from. |
| `config/persona/USER.md` | `config/persona/` | שם אישי, telegram handle, chat_id. |
| `data/` (כל הקבצים) | `data/` | DBs עם היסטוריית שיחות, IoCs, memory. |
| `logs/` (כל הקבצים) | `logs/` | לוגים עם chat_id, נתיבים, פעילות. |
| `memory/` (כל הקבצים) | `memory/` | זיכרונות אישיים של המשתמש. |
| `state/` (כל הקבצים) | `state/` | מצב runtime עם נתונים אישיים. |
| `downloads/` (כל הקבצים) | `downloads/` | קבצים אישיים (חוזים, מסמכים). |

> **הרחבה:** אם נוצר גיבוי/ZIP/archive חדש שמכיל דאטה רגיש — הוסף אותו לטבלה כאן לפני שמשתפים דבר.

---

## הצ'קליסט (5 סעיפים, כולם חייבים PASS)

### סעיף 1 — gitleaks על העץ

```powershell
gitleaks detect --no-git --source . --config .gitleaks.toml
```

- **PASS:** `no leaks found` (exit code 0)
- **FAIL:** כל ממצא. דווח: RuleID, File, Line, Secret (מסופח).

### סעיף 2 — חיפושי PII ידניים

הרץ את החיפושים הבאים על קבצים שייכנסו לשיתוף/קומיט (לא על קבצים מוחרגים).
הדפוסים גזורים מטבלת הממצאים המלאה של דוח שלב 1 (סעיף ב') — לא רשימה גנרית.

> **מקור ה-PII:** הערכים האמיתיים נמצאים בקבצי הקונפיג המוחרזים (`config/trusted_devices.json`, `config/channels.json`, `config/news_feeds.json`, `config/persona/USER.md`). קרא אותם ב-runtime כדי לבנות את הדפוסים המדויקים. אל תכתוב את הערכים האמיתיים בקובץ הזה.

#### 2a. נתיבי משתמש (כל וריאציה)
```
grep -rnE '[Cc]:[/\\][Uu]sers[/\\][a-zA-Z]' --include='*.py' --include='*.md' --include='*.json' --include='*.yml' --include='*.yaml' .
```
סווג כל התאמה:
- **FOUND:** נתיב עם שם משתמש אמיתי (קרא את שם המשתמש מ-`config/persona/USER.md` או מה-OS)
- **REMEDIATED:** היה נתיב אמיתי ותוקן לגנרי (לדוגמה `C:\Users\user`) — **לא false positive!**
- **FALSE-POSITIVE:** מעולם לא היה ממצא (לדוגמה `C:\Users\attacker` בטסט תוקף)

#### 2b. שמות קבצים אישיים
```
grep -rnE 'חוזה_אלירן|אלירן_ובת|\.kcpps' --include='*.py' --include='*.md' .
```
- **FOUND:** שם קובץ אישי אמיתי (חוזה עם שמות, קובץ קונפיג עם שם אישי)
- **REMEDIATED:** שונה לגנרי (לדוגמה `sample_contract.pdf`, `kobold.kcpps`)
- **FALSE-POSITIVE:** חלק ממילה תקינה (לדוגמה "סינכרוני" מכיל "רוני")

#### 2c. hostnames אישיים
```
grep -rnE '<hostname>-PC|<hostname>-PC-Bot' --include='*.py' --include='*.md' --include='*.json' .
```
(החלף `<hostname>` בשם המחשב האמיתי מ-`config/persona/USER.md` או מה-OS)
- **FOUND:** hostname אישי אמיתי
- **REMEDIATED:** שונה לגנרי (לדוגמה `tactical_bot`)
- **FALSE-POSITIVE:** אין — כל התאמה היא ממצא או תיקון

#### 2d. handles של טלגרם + chat_id
```
grep -rnE 'chat_id.{0,6}[0-9]{7,}' --include='*.py' --include='*.md' --include='*.json' .
```
בנוסף, קרא את ה-chat_id האמיתי מ-`config/channels.json` (שדה `allow_from`) ומ-`config/news_feeds.json` (שדה `delivery.telegram.chat_id`), וחפש אותו ישירות:
```
grep -rnE '<real_chat_id>' --include='*.py' --include='*.md' --include='*.json' .
```
(החלף `<real_chat_id>` בערך מהקונפיג — אל תכתוב אותו כאן)
- **FOUND:** handle אישי או chat_id אמיתי בקובץ שייכנס לשיתוף
- **REMEDIATED:** הוחרז/הוחלף ל-env var (`${TELEGRAM_CHAT_ID}`)
- **FALSE-POSITIVE:** chat_id בקובץ example עם `${TELEGRAM_CHAT_ID}` (פיקטיבי)

#### 2e. MAC אמיתיים
קרא את רשימת ה-MAC מ-`config/trusted_devices.json` (שדה `mac` בכל רשומה), וחפש כל אחד:
```
grep -rnE '<mac1>|<mac2>|...' --include='*.py' --include='*.md' --include='*.json' .
```
(החלף את ה-MACs בערכים מהקונפיג — אל תכתוב אותם כאן)
- **FOUND:** MAC אמיתי מהרשת הביתית בקובץ שייכנס לשיתוף
- **REMEDIATED:** הוחרז ל-`.example.json` עם `00-00-00-00-00-01`
- **FALSE-POSITIVE:** `00-00-00-00-00-01` בקובץ example (פיקטיבי)

#### 2f. שם/כינויים אישיים
קרא את השם האישי וה-handle מ-`config/persona/USER.md`, וחפש:
```
grep -rnE '<real_name>|<real_handle>' --include='*.py' --include='*.md' --include='*.json' .
```
(החלף בערכים מהקונפיג — אל תכתוב אותם כאן)
- **FOUND:** שם אישי אמיתי בקובץ שייכנס לשיתוף
- **REMEDIATED:** הוחרז/הוסר (לדוגמה USER.md → USER.example.md)
- **FALSE-POSITIVE:** "סינכרוני", "אחרונים", "פרוניט", "אלקטרוניקה" (מילים עבריות שמכילות תת-מחרוזת)

> **כלל סיווג קריטי:** ממצא שתוקן לעולם לא מסווג FALSE-POSITIVE. REMEDIATED = היה ממצא אמיתי וטופל. FALSE-POSITIVE = מעולם לא היה ממצא. ערבוב הקטגוריות ילמד את הסקיל לסנן ממצאים אמיתיים דומים בעתיד.

### סעיף 3 — git status נקי מקבצים רגישים

```powershell
git status --short
```

בדוק שלא מופיעים בפלט:
- `logs/`
- `state/`
- `data/`
- `memory/`
- `downloads/`
- `config/trusted_devices.json`
- `config/news_feeds.json`
- `config/channels.json`
- `config/persona/USER.md`
- `.env`
- `.devin/config.local.json`

- **PASS:** אף אחד מהם לא מופיע
- **FAIL:** אחד מהם מופיע — הוא ייכנס לקומיט/שיתוף. עצור.

### סעיף 4 — קבצי .example נקיים מערכים אמיתיים

לכל קובץ `.example`, השווה מול המקבילה האמיתית (אם קיימת על הדיסק):

| Example | Real | בדיקה |
|---------|------|-------|
| `config/trusted_devices.example.json` | `config/trusted_devices.json` | אסור MAC/IP אמיתי. מותר רק `00-00-00-00-00-01` + `10.0.0.100` |
| `config/news_feeds.example.json` | `config/news_feeds.json` | אסור chat_id אמיתי. מותר רק `${TELEGRAM_CHAT_ID}` |
| `config/channels.example.json` | `config/channels.json` | אסור chat_id/bot_token אמיתי. מותר רק env vars |
| `config/persona/USER.example.md` | `config/persona/USER.md` | אסור שם/handle/chat_id אמיתי. מותר רק placeholders |

- **PASS:** אף ערך אמיתי לא משותף בין הקבצים (רק מבנה)
- **FAIL:** ערך אמיתי מופיע ב-example. עצור.

### סעיף 5 — רשימת "לעולם לא לשתף" מעודכנת

- **PASS:** הרשימה בראש הסקיל מכילה את כל הקבצים הרגישים הנוכחיים
- **FAIL:** נוצר גיבוי/ZIP/archive חדש שלא רשום. הוסף לפני שיתוף.

---

## פלט — טבלת PASS/FAIL

הפק את הטבלה הבאה בסיום:

```
| סעיף | תיאור | תוצאה | הערות |
|------|--------|-------|-------|
| 1 | gitleaks | PASS/FAIL | ... |
| 2a | נתיבי משתמש | PASS/FAIL | N FOUND, N REMEDIATED, N FP |
| 2b | שמות קבצים אישיים | PASS/FAIL | ... |
| 2c | hostnames | PASS/FAIL | ... |
| 2d | handles + chat_id | PASS/FAIL | ... |
| 2e | MAC אמיתיים | PASS/FAIL | ... |
| 2f | שם/כינויים | PASS/FAIL | ... |
| 3 | git status נקי | PASS/FAIL | ... |
| 4 | .example נקיים | PASS/FAIL | ... |
| 5 | רשימת "לעולם לא" מעודכנת | PASS/FAIL | ... |
```

**FAIL אחד = עצירה.** דווח למשתמש, אל תמשיך לפעולה החיצונית.

---

## מתי לא להריץ
- עריכת קוד פנימית שלא משתפת עם גורם חיצוני — לא צריך את הצ'קליסט המלא.
- אבל: קומיט ל-main, יצירת ZIP, push ל-remote, שליחת קובץ למישהו — **חובה**.
