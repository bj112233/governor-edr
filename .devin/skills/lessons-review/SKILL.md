---
name: lessons-review
description: Read tasks/lessons.md and surface lessons relevant to the current task or recent changes
argument-hint: "[optional topic/keyword]"
allowed-tools:
  - read
  - grep
  - glob
triggers:
  - user
  - model
---

Review the project's accumulated lessons and surface the ones relevant to the current work.

## Steps

1. **Read the lessons file**: Read `tasks/lessons.md` in full. If it does not exist, report that no lessons have been captured yet and stop.

2. **Identify relevance**: If an argument ($ARGUMENTS) is given, filter lessons whose title, mistake, root cause, or rule mentions the topic/keyword. If no argument, consider the current git diff (`git diff --staged` or `git diff`) to infer what the user is working on, then match lessons to the touched files/concepts.

3. **Surface relevant lessons**: For each relevant lesson, output a compact block:
   ```
   ### [date] Title
   - Rule: <the rule line>
   - Applies because: <one sentence why it's relevant to the current change>
   ```

4. **If nothing relevant**: State "No lessons in tasks/lessons.md match the current work" and list the lesson titles that exist (date + title only) so the user can see what's available.

## Rules
- Do NOT modify `tasks/lessons.md` — this skill is read-only review.
- Do NOT restate the full lesson text; extract only the Rule line + a one-sentence relevance note.
- If the lessons file is large, prioritize the 5 most relevant lessons over exhaustive listing.
