---
name: arch-update
description: Update docs/ARCHITECTURE.md (and conceptual_repo/ARCHITECTURE.md if it references the same facts) after a significant commit, then commit atomically as docs(arch)
argument-hint: "[commit-sha or description of what changed]"
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

Update the architecture docs to reflect a significant code change, then commit the docs update as a SEPARATE atomic commit. This enforces AGENTS.md §4: "After every significant commit (refactor, feature, architectural change): update docs/ARCHITECTURE.md (and conceptual_repo/ARCHITECTURE.md if it references the same facts) and commit the docs update ATOMICALLY as its own separate commit (docs(arch): ...), never bundled into the code commit."

## When to invoke
- After a refactor, feature, or architectural change has ALREADY been committed (code commit done).
- NOT for trivial changes (typo, comment, single-line fix).

## Steps

1. **Identify what changed**: If an argument ($ARGUMENTS) is given, use it (commit SHA or description). Otherwise run `git log --oneline -5` and `git show HEAD --stat` to identify the most recent significant commit. Determine which architectural facts were affected: file paths, function names, constants, counts, module structure, data flow, gate thresholds.

2. **Read the current docs**: Read `docs/ARCHITECTURE.md` (the internal reference, ~88KB, 18 sections). Identify every section that references the changed facts. Also read `conceptual_repo/ARCHITECTURE.md` and check if it references the same facts (it is a trimmed public variant).

3. **Verify facts against code**: Do NOT trust the old doc text. Re-verify every changed fact against the actual codebase:
   - File paths: `glob` / `Get-ChildItem`
   - Function/class names: `grep`
   - Counts (bypass handlers, skills, gates): count them in the source
   - Gate thresholds: read `.xenon.yml`, `.cognitive_baseline.txt`, `.coverage_baseline.txt`, `.file_length_baseline.txt`
   - Mermaid diagrams: verify node labels match actual module names

4. **Edit the docs**: Use `edit` to update ONLY the affected lines/sections. Do NOT rewrite the whole file. Preserve the existing structure (Table of Contents, Mermaid diagrams, section numbering). Update the "verified against codebase" date stamp at the top if present.

5. **Commit atomically**: Stage ONLY the docs files and commit with prefix `docs(arch):`:
   ```
   git add docs/ARCHITECTURE.md conceptual_repo/ARCHITECTURE.md
   git commit -F .commit_msg.txt
   ```
   Commit message format: `docs(arch): reflect <short description of what changed>`
   Example: `docs(arch): reflect credential_format.py extraction + gate table fixes`

## Rules
- NEVER bundle docs updates into a code commit. The docs commit is SEPARATE and comes AFTER the code commit.
- NEVER regenerate the entire ARCHITECTURE.md from scratch unless structurally unavoidable — edit the affected sections only.
- NEVER update a fact without re-verifying it against the codebase. Stale facts are worse than no docs.
- If `conceptual_repo/ARCHITECTURE.md` does NOT reference the changed facts, do not touch it (avoid noise).
- Use `.\.venv\Scripts\python.exe` for any Python verification — never bare `python` (venv hook enforces this).
- Clean up `.commit_msg.txt` scratch file after commit.
