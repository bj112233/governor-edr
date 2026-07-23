---
name: ratchet
description: After a refactor that reduced complexity or violations, tighten the ratchet baselines (.xenon.yml, .cognitive_baseline.txt, .coverage_baseline.txt, .file_length_baseline.txt) to lock in the gain
argument-hint: "[which gate: xenon|cognitive|coverage|file-length|all]"
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

Tighten the ratchet baselines after a refactor that reduced complexity, increased coverage, or removed dead code. This enforces AGENTS.md §4: "Ratchet protocol: extract one block per commit; never lower threshold below proven CC." The ratchet only tightens — never loosen a threshold below its proven value.

## The 4 ratchet baselines

| Gate | Baseline file | Regenerate command |
|------|---------------|-------------------|
| Cyclomatic Complexity (xenon) | `.xenon.yml` | manual edit (max-absolute, max-average, max-modules) |
| Cognitive Complexity | `.cognitive_baseline.txt` | `.\.venv\Scripts\python.exe bin\cognitive_complexity_gate.py --regenerate` |
| Coverage | `.coverage_baseline.txt` | `.\.venv\Scripts\python.exe bin\coverage_gate.py --regenerate` |
| File Length | `.file_length_baseline.txt` | manual edit (remove shrunk/extracted files) |

## When to invoke
- After a refactor that REDUCED complexity (extracted a function, split a class, simplified a branch).
- After adding tests that INCREASED coverage %.
- After extracting a block that moved a file below the LLOC threshold.
- NOT after changes that didn't move any metric.

## Steps

1. **Determine which gate(s)**: If $ARGUMENTS specifies a gate, focus on it. Otherwise run all 4 gates to see which improved:
   ```
   .\.venv\Scripts\python.exe bin\lint-gate.py --fast
   ```
   Note: `--fast` skips the coverage gate. To check coverage, run `.\.venv\Scripts\python.exe bin\coverage_gate.py` separately (it reuses cached `coverage.json` if fresh <10 min).

2. **For each improved gate, regenerate the baseline**:

   ### Cognitive Complexity
   - Run: `.\.venv\Scripts\python.exe bin\cognitive_complexity_gate.py --regenerate`
   - This rewrites `.cognitive_baseline.txt` with the current (smaller) violation set.
   - Verify the new baseline has FEWER lines than before (ratchet only shrinks).

   ### Coverage
   - Run: `.\.venv\Scripts\python.exe bin\coverage_gate.py --regenerate`
   - This rewrites `.coverage_baseline.txt` from the cached `coverage.json`.
   - If `coverage.json` is stale (>10 min since last code change), run `--fresh` first to force a pytest re-run. WARNING: `--fresh` runs the full 200+ test suite — takes minutes. Only use if explicitly needed.
   - Verify the new `Total:` line is ≥ the old value (ratchet only rises).

   ### File Length
   - Read `.file_length_baseline.txt`. For each file that was refactored (split/extracted), check its current LLOC:
     `.\.venv\Scripts\python.exe -c "import sys; sys.path.insert(0,'bin'); from file_length_gate import _count_lloc; print(_count_lloc('path/to/file.py'))"`
   - If a file is now ≤300 LLOC, remove its line from the baseline. If a file was deleted, remove its line.
   - NEVER add files to the baseline — that's loosening, not tightening.

   ### Xenon (.xenon.yml)
   - Run `.\.venv\Scripts\python.exe -m xenon services/ --max-absolute D --max-average A --max-modules C` and check the actual average grade.
   - If the actual average is now better than the threshold (e.g. threshold is B but actual is A), edit `.xenon.yml` to tighten `max-average` to the proven grade.
   - NEVER loosen a threshold (e.g. A→B). Only tighten (B→A, or lower the max-absolute from E→D).
   - Update the comment block in `.xenon.yml` to reflect the new state.

3. **Verify the gate still passes** with the new baseline:
   ```
   .\.venv\Scripts\python.exe bin\lint-gate.py --fast
   ```
   If it fails, the baseline was tightened too aggressively — revert and use a less aggressive value.

4. **Report**: Summarize what was tightened:
   | Gate | Before | After | Change |
   |------|--------|-------|--------|

## Rules
- The ratchet ONLY tightens. NEVER loosen a threshold or add entries to a baseline.
- ALWAYS verify the gate passes after regenerating — a baseline the gate fails on is useless.
- Use `--regenerate` (cache reuse, seconds) over `--fresh` (full pytest, minutes) unless the cache is stale.
- Use `.\.venv\Scripts\python.exe` for all commands — the venv hook blocks bare `python`.
- Do NOT commit baseline changes unless explicitly asked — the user may want to review.
- If a refactor did NOT improve any metric, state "No ratchet tightening needed — no metrics improved" and stop.
