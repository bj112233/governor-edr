---
name: windows-shell
description: כללי עבודה ב-PowerShell/Windows עבור tactical_bot — מונע שגיאות `&&`, נתיבים, ושימוש ב-venv
triggers:
  - user
  - model
---

# Windows / PowerShell — כללים הכרחיים (tactical_bot)

הסביבה היא **Windows + PowerShell 5** ו-**Python 3.12.2 ב-venv**. פקודות bash/POSIX נכשלות כאן. השתמש בכללים הבאים **תמיד** כשאתה מריץ פקודות ב-`exec`.

## הבדלים קריטיים מ-bash

| bash | PowerShell | הערה |
|------|-----------|------|
| `cmd1 && cmd2` | `cmd1 ; cmd2` | **אין `&&` ב-PowerShell 5.** השתמש ב-`;`. להרצה מותנית: `cmd1 ; if ($?) { cmd2 }` |
| `cmd1 \|\| cmd2` | `if (-not $?) { cmd2 }` | אין `\|\|` ישיר |
| `cd /path` | `cd path` או `Set-Location` | backslash, לא forward slash (בנתיבים מקומיים) |
| `test -f file` | `Test-Path file` | |
| `mkdir -p a/b` | `New-Item -ItemType Directory a/b -Force` | |
| `rm -rf x` | `Remove-Item x -Recurse -Force` | |
| `cp a b` | `Copy-Item a b` | (יש alias `cp` אבל התחביר שונה) |
| `mv a b` | `Move-Item a b` | |
| `cat file` | `Get-Content file` | (יש alias `cat`) |
| `ls -la` | `ls` או `Get-ChildItem` | `ls` מחזיר טבלה; לשמות בלבד: `ls -Name` |
| `$VAR` | `$env:VAR` | משתני סביבה |
| `echo $?` | `$LASTEXITCODE` | exit code של תוכנית חיצונית |
| `export VAR=x` | `$env:VAR = "x"` | |
| `source venv/bin/activate` | `.\.venv\Scripts\Activate.ps1` | הפעלת venv ב-Windows |

## כללי זהב
1. **אף פעם לא `&&`** — השתמש ב-`;` בין פקודות. אם צריך מותנה, `; if ($?) { ... }`.
2. **נתיבים עם backslash** ב-Windows: `C:\Users\<user>\tactical_bot\...`. ה-exec tool מקבל גם forward slash בחלק מהמקרים, אבל backslash עדיף לנתיבים מקומיים.
3. **צרף נתיבים עם רווחים בגרשיים כפולים**: `cd "C:\My Folder"`.
4. **`ls` מחזיר טבלה ארוכה** — אם רוצה רק שמות: `ls -Name`, או `Get-ChildItem -Name`.
5. **exit code**: אחרי תוכנה חיצונית (python, pytest, git) בדוק `$LASTEXITCODE` או `$?`.

## Python interpreter — קריטי (נאכף ע"י hook)
- **ה-interpreter היחיד התקין**: `.\.venv\Scripts\python.exe` (Python 3.12.2).
- **אסור**: `python`, `python.exe`, `py -3`, `py -3.14`, system Python. `py` launcher מביא ל-Python 3.14 חסר תלויות.
- **תמיד**: `.\.venv\Scripts\python.exe -m pytest`, `.\.venv\Scripts\python.exe bin\lint-gate.py`, וכו'.
- **או הפעלה מפורשת תחילה**: `.\.venv\Scripts\Activate.ps1` ואז `$env:VIRTUAL_ENV` מתמלא.
- **PreToolUse hook** (`.devin/hooks.v1.json` → `bin/enforce-venv-hook.ps1`) חוסם exec שעוקף venv. **אל תעקוף.**
- **לאכלוס venv**: `Get-ChildItem -Force .venv\Scripts\python.exe`. `find_by_name`/`glob` מכבדים `.gitignore` ומדלגים על `.venv` — לא להסיק "אין venv" מהם.

## דוגמה — רצף פקודות
```powershell
# רע: python -m pytest && python bin/lint-gate.py
# טוב:
.\.venv\Scripts\python.exe -m pytest ; if ($?) { .\.venv\Scripts\python.exe bin\lint-gate.py }
```

```powershell
# בדיקת קיום + יצירה
if (-not (Test-Path .devin\skills)) { New-Item -ItemType Directory .devin\skills -Force }
```

```powershell
# הפעלת venv ובדיקה
.\.venv\Scripts\Activate.ps1 ; $env:VIRTUAL_ENV ; & .\.venv\Scripts\python.exe --version
```

## מתי לא להשתמש ב-skill הזה
- פקודות שעוברות ל-`python`/`pytest` עצמן — עדיין צריך להשתמש ב-venv הנכון, אבל התחביר פנימי שלהן לא PowerShell.
- סקריפטים שרצים דרך `python -m` — הם לא PowerShell.

אם פקודה נכשלת עם "The token '&&' is not a valid statement separator" — זה הסימן שעברת על הכלל הזה. תקן מייד.
אם פקודה נכשלת עם `ModuleNotFoundError` / `ImportError` — כנראה השתמשת ב-system Python במקום venv. תקן מייד.
