---
name: commit
description: Create a git commit following the project's conventional-commit format, then auto-trigger the arch-update skill for the separate atomic docs(arch) commit when the change is significant. Enforces AGENTS.md §4 (atomic docs commit, never bundled into code).
argument-hint: "[optional commit message hint]"
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

Create a git commit using the project's established conventional-commit format, then — if the change is significant (refactor, feature, architectural) — invoke the `arch-update` skill to produce the separate atomic `docs(arch):` commit. The two commits are NEVER bundled (AGENTS.md §4).

## When to invoke
- When the user asks to commit, save, or "ship" the current work.
- After implementation + verification (`verify` skill) is complete and gates pass.
- NOT for empty working trees (run `git status` first; if clean, stop).
- NOT for work-in-progress snapshots the user wants to stash instead.

## Steps

1. **Gather state in parallel** (single tool block):
   - `git status` — what's staged/unstaged
   - `git diff` (unstaged) + `git diff --staged` — what changed
   - `git log --oneline -10` — match the project's commit style

2. **Classify the change** by reading the diff:
   - `fix(scope):` — bug fix, regression fix, security hardening
   - `feat(scope):` — new capability, new module, new detection rule
   - `refactor(scope):` — internal restructuring with no behavior change (extraction, split, rename)
   - `docs(arch):` — architecture doc update (handled by `arch-update`, NOT this skill)
   - `docs(lessons):` — lessons.md update
   - `chore(ratchet):` — baseline tightening
   - `test(scope):` — test-only change
   - `perf(scope):` — performance improvement
   - Scope = module or feature name (e.g. `fingerprint`, `metrics_db`, `self-whitelist`, `breaking_news`).

3. **Draft the message** — focus on WHY, not WHAT (the diff shows what). One short imperative line ≤72 chars for the subject. If a body is needed, blank line + body wrapped at 72. Check for secrets/keys/PII in the diff before drafting — NEVER commit secrets.

4. **Stage + commit**:
   ```
   git add <specific files>          # do NOT use `git add .` unless everything is intentional
   git commit -m "$(cat <<'EOF'
   <subject>

   <optional body>
   EOF
   )"
   ```
   - If a pre-commit hook modifies files and the commit fails, re-stage the modified files and retry once. If it fails again, stop and report.

5. **Decide on the docs commit**:
   - **Significant** (refactor, feature, architectural change, new module, threshold change, new gate, file split/extract, new detection path): invoke the `arch-update` skill next to produce the atomic `docs(arch):` commit. Do NOT write the docs commit yourself — `arch-update` re-verifies facts against the codebase first.
   - **Trivial** (typo, comment, single-line fix, test-only, baseline bump): skip `arch-update`. State "Trivial change — no docs(arch) commit needed."
   - If unsure, lean toward invoking `arch-update` — stale docs are worse than a small docs commit.

6. **Report**: One-line confirmation with the commit SHA + subject, and whether `arch-update` was triggered.

## Rules
- NEVER bundle a docs/ARCHITECTURE.md update into the code commit. The docs commit is SEPARATE and produced by `arch-update` AFTER the code commit.
- NEVER use `git push` — it is in the deny list. Push only when the user explicitly asks.
- NEVER commit secrets — scan the diff for keys, tokens, passwords, connection strings before staging.
- NEVER use `git add .` or `git add -A` blindly — stage specific files so WIP/experimental files don't leak in.
- NEVER update git config.
- NEVER use `-i` flags (interactive mode not supported).
- Match the project's commit style exactly (see `git log --oneline -10`). The scope is lowercase, hyphen-separated, no spaces.
- Use `.\.venv\Scripts\python.exe` for any Python verification — never bare `python`.
- If `git status` shows a clean tree, state "Nothing to commit — working tree clean" and stop.
