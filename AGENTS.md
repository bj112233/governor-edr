# Sentinel Project Rules

## 1. Token Economy & Output Restraints (CRITICAL PRIORITY)
- Zero-Fluff: Omit all greetings, pleasantries, generic summaries, and conversational filler.
- Diff-Only Code: When modifying existing code, output ONLY the specific function, class, or lines that changed. NEVER rewrite the entire file unless structurally unavoidable. Use comments like `# ... existing code ...` to skip unmodified sections.
- On-Demand Explanation: DO NOT explain the "Why" or the underlying engineering principles unless explicitly requested in the prompt. Default to providing ONLY the minimalist, production-ready solution.
- Action Over Words: If a logic error is identified, output the direct factual correction without prefacing or apologizing (Adversarial Truth).

## 2. Technical Scope & Work Style
- Software: Python, strict typing, Pydantic V2, and asynchronous architecture. Enforce Single Responsibility Principle (max 300 lines per file).
- Hardware/Systems: Class D amplification (TPA3255), Acoustic Engineering, Li-ion power management, Microservices, and Containerized environments (Docker).
- Analytical Approach: Apply First Principles Thinking. Rely on official documentation, datasheets, and physics/math over conventions.

## 3. Output Standards (When Explanation is Requested)
- Format: High-level technical Hebrew (Level 150).
- Structure: Use tables, bullet points, and headers for maximum scanability.
- Precision: Include specific numerical values, component identifiers, and precise formulas where applicable.

## 4. Task Management
- Session start: ALWAYS read `tasks/lessons.md` first before starting any work.
- Plan: `tasks/todo.md` + `tasks/lessons.md`
- Verification: run `.\.venv\Scripts\python.exe bin\lint-gate.py` before declaring done
- Ratchet protocol: extract one block per commit; never lower threshold below proven CC
- Coverage ratchet policy (CRITICAL — prevents the ratchet from becoming a "make CI
  pass" knob):
  - Baseline file: `.coverage_baseline.txt`. Regenerate via
    `.\.venv\Scripts\python.exe bin\coverage_gate.py --regenerate`.
  - **When to raise**: after adding tests that increase coverage. Regenerate
    baseline in the SAME commit as the tests (commit message: `test: ...`).
  - **When to lower**: ONLY when coverage drops due to legitimate code changes
    (e.g., dependency upgrade makes a fallback branch unreachable, Windows-only
    API function becomes untestable). Must be a SEPARATE commit
    (`fix(ci): lower coverage baseline — <justification>`), never bundled into a
    feature PR. The commit message MUST explain which functions lost coverage
    and why it's untestable.
  - **Never lower for**: deleted tests, skipped tests, or "the test is flaky".
    If a test is flaky, fix it or mark `pytest.mark.skip` with a reason — do not
    remove it from the baseline.
  - **Dependabot bumps**: if a bump legitimately drops coverage (runtime
    behavior drift), lower the baseline in a follow-up commit with justification.
    Do NOT lower as part of the bump merge itself.
  - **Baseline must match CI**: regenerate without `.env` (CI has no `.env`).
    `Move-Item .env .env.tmp; ... --regenerate; Move-Item .env.tmp .env`.
- After every significant commit (refactor, feature, architectural change): update
  `docs/ARCHITECTURE.md` (and `conceptual_repo/ARCHITECTURE.md` if it references the
  same facts) and commit the docs update ATOMICALLY as its own separate commit
  (`docs(arch): ...`), never bundled into the code commit.

## 5. Python Interpreter (CRITICAL — enforced by hook)
- The ONLY correct interpreter is `.\.venv\Scripts\python.exe` (Python 3.12.2). `$env:VIRTUAL_ENV` is empty on session start; bare `python` is not on PATH; `py` launcher defaults to system Python 3.14 which lacks project deps.
- NEVER use bare `python`, `python.exe`, `py -3`, `py -3.14`, or system Python for any task (tests, lint, imports, scripts).
- Always invoke: `.\.venv\Scripts\python.exe -m pytest`, `.\.venv\Scripts\python.exe bin\lint-gate.py`, etc. Or activate first: `.\.venv\Scripts\Activate.ps1`.
- A PreToolUse hook (`.devin/hooks.v1.json` → `bin/enforce-venv-hook.ps1`) actively blocks exec calls that bypass the venv. Do not work around it.
- To confirm venv presence: `Get-ChildItem -Force .venv\Scripts\python.exe`. Never conclude "no venv" from `find_by_name`/`glob` — they respect `.gitignore` and skip `.venv`.
