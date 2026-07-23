---
name: verify
description: Run project verification gates (lint-gate --fast + targeted pytest -x) and summarize status
argument-hint: "[optional test path]"
allowed-tools:
  - read
  - grep
  - glob
  - exec
triggers:
  - user
  - model
---

Run the Sentinel project verification gates and report status. Do NOT skip steps.

## Steps

1. **Read lessons first**: Read `tasks/lessons.md` and note any lesson relevant to the change being verified (e.g. LLOC vs physical lines, coverage cache freshness, venv-only interpreter).

2. **Lint gate (fast)**: Run `.\.venv\Scripts\python.exe bin\lint-gate.py --fast`
   - This skips the coverage gate (200+ tests) per lesson L1. Use `--fast` for routine verification.
   - Full `lint-gate.py` (with coverage) only when explicitly requested — it hangs for minutes.
   - Parse the output: list each gate that FAILED with its specific error.

3. **Targeted tests**: Run `.\.venv\Scripts\python.exe -m pytest -x $ARGUMENTS`
   - If no path argument given, ask the user which test file/module to target. Do NOT run the full suite unprompted.
   - `-x` = fail-fast (stop on first failure). Per `.devin/config.json` this is the only pytest form auto-approved.
   - If a test fails, read the failure traceback, identify the root cause, and report it. Do not fix unless asked.

4. **Summarize**: Report a compact status table:
   | Gate | Status | Notes |
   |------|--------|-------|
   List any failures with file:line references. If all pass, state "ALL GATES PASSED — ready to commit".

## Rules
- NEVER use bare `python`, `python.exe`, or `py -3` — the venv hook blocks these. Always `.\.venv\Scripts\python.exe`.
- NEVER run `lint-gate.py` without `--fast` unless the user explicitly asks for full coverage.
- NEVER run `pytest` without `-x` unless the user explicitly asks for the full suite.
- If a gate fails, report the failure factually — do not paper over it.
