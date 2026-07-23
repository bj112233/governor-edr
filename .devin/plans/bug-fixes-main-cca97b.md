# תיקון 9 באגים ב-main.py + ai_module.py

תוכנית לתיקון כל 9 הבאגים שזוהו בסריקת הקוד, תוך שמירה על ארכיטקטורת Fail-Fast + NSSM.

---

## קבצים מושפעים

| קובץ | פעולה |
|------|--------|
| `main.py` | שינויים מרובים |
| `ai_module.py` | הסרת `logging.basicConfig` |
| `logging_config.py` | **חדש** — הגדרת logging מרכזית |

---

## שלב 1 — `logging_config.py` (חדש)

צור `logging_config.py` שחושף פונקציה `setup_logging()`.  
- מגדירה `level`, `format` אחידים לכל ה-process.  
- `main.py` קורא לה פעם אחת בתחילת `main()`.  
- `ai_module.py` מסיר את ה-`basicConfig` הכפול (**באג #7**).

---

## שלב 2 — תיקונים ב-`main.py`

### #1 — Silent LAN Task Failure (שורה 175)
- הוסף `exc_info=True` ל-`logger.error` בתוך `_scan_lan_background`.
- שמור את ה-task ב-variable: `lan_task = asyncio.create_task(...)`.
- הוסף `done_callback` כרשת ביטחון: `lambda t: logger.error(...) if t.exception() else None`.

### #3 — Exception Re-throwing (שורות 228-232)
- הסר `raise exc`.
- החלף ב-`logger.critical(..., exc_info=exc)` בלבד.
- `main()` יחזור בשקט → `asyncio.run()` יסיים → NSSM יאתחל.

### #4 — Global Bot Instance (שורה 34)
- הזז `bot = Bot(token=BOT_TOKEN)` מ-global scope לתוך `main()`.
- הוסף `bot` כפרמטר ל-`daily_digest_loop(bot)` ו-`monitor_loop(bot)`.
- עדכן את קריאות `asyncio.create_task(...)` בהתאם.

### #5 — Redundant String Check (שורה 112)
- שנה: `ai_analysis.strip() == ""` → `not ai_analysis.strip()`

### #6 — Monitor Loop Cooldown Logic (שורות 159-161)
- בחלק ה-`except`: שנה `asyncio.sleep(20)` → `asyncio.sleep(600)`.
- הוסף `exc_info=True` ל-`logger.error` + הודעת cooldown.

### #8 — Graceful Shutdown
- עטוף את ה-`asyncio.wait(...)` בבלוק `try/finally`.
- בבלוק `finally`: בטל tasks פעילים + `await bot.session.close()` + לוג סגירה.

### #9 — Health Check / Heartbeat
- הוסף `logger.debug(f"💓 monitor heartbeat")` בלולאת `monitor_loop`.
- הוסף `logger.info(f"📅 digest heartbeat | next={next_run}")` בלולאת `daily_digest_loop`.

---

## שלב 3 — תיקון ב-`ai_module.py`

### #7 (המשך)
- מחק שורות 12-14 (`logging.basicConfig(...)`).
- `logger = logging.getLogger(__name__)` נשאר — יורש את ה-config מ-`main.py`.

---

## הערות אדריכליות

- **באג #2**: ה-`asyncio.wait(FIRST_COMPLETED)` **נשמר** (Fail-Fast). תוקנו רק logging והסרת `raise exc`.
- **300-line limit**: `main.py` עומד על 242 שורות. ההוספות הצפויות (~25 שורות) ישאירו אותו מתחת ל-270.
- **Windows compatibility**: `loop.add_signal_handler` אינו נתמך ב-Windows (ProactorEventLoop). ה-Graceful Shutdown מסתמך על `finally` block שרץ גם ב-KeyboardInterrupt.
