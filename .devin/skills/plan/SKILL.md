---
name: plan
description: Write or refresh tasks/todo.md at the start of a non-trivial task, after reading tasks/lessons.md. Enforces global_rules §1 (Plan First) and AGENTS.md §4 (Plan: tasks/todo.md + tasks/lessons.md).
argument-hint: "[short task title]"
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

Write a checkable plan to `tasks/todo.md` BEFORE starting implementation on any non-trivial task (3+ steps, architectural decision, or multi-file change). This is the planning half of the workflow; `lessons-review` is the input half. Together they enforce "Plan First, Verify Plan, Track Progress" from global_rules.

## When to invoke
- Start of a non-trivial task (3+ steps, refactor, feature, architectural change, multi-file fix).
- When the user describes a goal but no concrete steps have been written yet.
- NOT for trivial single-line fixes, typos, or pure questions (use `lessons-review` alone for those).

## Steps

1. **Read lessons first**: Read `tasks/lessons.md` in full. Identify lessons whose Rule applies to the upcoming task (same module, same pattern class — JSON parsing, LLM call site, filter chain, env paths, SQLite migration, etc.). These become constraints on the plan.

2. **Read the existing todo**: Read `tasks/todo.md`. It already contains prior plans (kept as a running log). Do NOT overwrite — append a new section at the top (most recent first) or extend the current active section. If a section is marked complete (all `[x]`), leave it and add a new `#` section above it.

3. **Verify what's already done**: Run `git log --oneline -15` and cross-reference the user's request against recent commits (per lesson [2026-06-28] stale orphan list). Do NOT plan work that's already committed. State "Already done in <sha>" if so.

4. **Draft the plan section** in the established format (see existing entries):
   ```
   # <Short title> — <one-line context> (<YYYY-MM-DD>)
   > **Trigger:** <what prompted this task>

   ## Plan
   - [ ] 1. <step> — <one-line detail of how>
   - [ ] 2. <step> — <one-line detail>
   ...

   ## Review
   <filled in after completion — see verify skill>
   ```
   - Each step must be a single, checkable action. If a step needs sub-steps, it's too coarse — split it.
   - Order steps so each one is independently verifiable.
   - Cap at ~7 steps; if more, group into phases.

5. **Embed lesson constraints**: For each relevant lesson from step 1, add a constraint line under the step it affects:
   ```
   - [ ] 3. Add SQLite migration — CONSTRAINT: ALTER TABLE ADD COLUMN only allows constant DEFAULTs (lesson 2026-07-06); backfill via UPDATE.
   ```

6. **Write the file**: Use `edit` to insert the new section. Preserve all existing sections (they are the audit trail). Update only the new section + the date stamp.

7. **Check in with the user**: Present the plan as a numbered list and ask for approval BEFORE implementing (global_rules §2 "Verify Plan: Check in before starting implementation"). Do NOT start coding until the user confirms — unless the user already said "just do it" / "go ahead" in the original request.

## Rules
- NEVER overwrite `tasks/todo.md` — always append/extend. Use `edit`, not `write` (lesson L6: overwrote 212 lines).
- NEVER plan work without first checking `git log` for prior commits that already did it (lesson [2026-06-28]).
- NEVER skip the lessons read — lessons are the constraints that make the plan correct, not just complete.
- If the task is trivial (1-2 steps, single file, no architectural impact), state "Trivial — skipping plan, proceeding directly" and do not write a todo section.
- Use `.\.venv\Scripts\python.exe` for any Python verification — never bare `python` (venv hook enforces this).
- Do NOT commit `tasks/todo.md` unless explicitly asked — it is a working file.
