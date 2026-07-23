---
name: lesson
description: Capture a new lesson in tasks/lessons.md after a user correction or a mistake discovered, following the established entry format
argument-hint: "[short title of the mistake]"
allowed-tools:
  - read
  - grep
  - glob
  - edit
  - exec
triggers:
  - user
  - model
---

Append a new lesson to `tasks/lessons.md` after a correction from the user or a mistake discovered during work. This enforces global_rules §3 (Self-Improvement Loop) and AGENTS.md §4 (Capture Lessons).

## When to invoke
- After the user corrects you on something you got wrong.
- After you discover a root-cause mistake that should not recur.
- NOT for trivial typos or one-off issues with no generalizable rule.

## Steps

1. **Identify the mistake**: Use $ARGUMENTS as the short title if provided. Otherwise infer a concise title (≤60 chars) from the recent correction. The title should describe the mistake, not the rule.

2. **Read the existing lessons file**: Read `tasks/lessons.md` in full. Check whether a similar lesson already exists (search by keyword). If a near-duplicate exists, EXTEND that entry with a new "Rule" line or update the existing one — do not create a redundant entry.

3. **Determine the date**: Run `Get-Date -Format "yyyy-MM-dd"` (or use today's date from context). Use the YYYY-MM-DD format per the existing entries.

4. **Draft the entry** following the exact format in the file header:
   ```
   ### [YYYY-MM-DD] Short title of the mistake
   - **Mistake**: What went wrong (specific, factual — name the function/file/behavior)
   - **Root cause**: Why it happened (the underlying reason, not just the symptom)
   - **Rule**: The rule to apply next time (imperative, generalizable, prevents recurrence)
   ```

5. **Append the entry**: Use `edit` to append the new entry at the END of the file (after the last entry, before any trailing whitespace). Preserve the file's existing structure (header, format block, entries in chronological order).

6. **Verify**: Read back the appended entry to confirm formatting matches the existing entries exactly (markdown headers, bold field labels, indentation).

## Rules
- NEVER delete or modify existing lessons unless explicitly asked — only append.
- NEVER create a lesson without a generalizable Rule. "Be more careful" is not a rule.
- The Rule must be actionable and prevent the SAME mistake class, not just the specific instance.
- Be specific in the Mistake field: name the function, file, or behavior. Vague lessons are useless.
- Root cause is NOT the same as the mistake — it's the underlying reason the mistake was possible.
- If `tasks/lessons.md` does not exist, create it with the standard header (see existing format).
- Do NOT commit the lesson file unless explicitly asked — the user may want to review first.
