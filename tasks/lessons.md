# Lessons Learned

> Updated after every correction. Rules to prevent repeating the same mistakes.

---

## Format

Each lesson entry:
```
### [YYYY-MM-DD] Short title of the mistake
- **Mistake**: What went wrong
- **Root cause**: Why it happened
- **Rule**: The rule to apply next time
```

### [2026-06-28] Directives injected as role:user were vulnerable to trimming
- **Mistake**: `_inject_directive` appended directives as `role:"user"` at the tail. `_trim_messages` only protects `role:"system"` messages (head + `_mid_system_msgs`). Directives could be evicted by progressive shrink, emergency overflow trim, or anchor misidentification.
- **Root cause**: Directive text wrapped the user question (`User question: {q}`) to double as the current-turn anchor. This conflated two invariants: "directive must survive" and "user question is the anchor". Under overflow, the wrapper was truncated before the question portion.
- **Rule**: Directives MUST be injected as `role:"system"` (protected by `_mid_system_msgs`). The user question MUST be a separate `role:"user"` message at the tail (the anchor). Never blend instruction + question into one message. `_emergency_trim_for_overflow` must also preserve mid-conversation system messages, not just `messages[0]`.

### [2026-06-28] File-length gate counts LLOC, not physical lines
- **Mistake**: Audit reported "13 production files exceed 300 lines" based on physical line counts. The gate (`bin/file_length_gate.py`) counts LLOC (excludes blanks, comments, docstrings). All 13 files were actually under 300 LLOC ג€” no baseline needed.
- **Root cause**: Subagent used `wc -l` equivalent (physical lines) instead of the gate's `_count_lloc` function. Docstrings and comments inflate physical counts significantly (e.g. `_agent_critic.py`: 402 physical ג†’ 287 LLOC).
- **Rule**: When auditing file-length violations, always use the gate's actual LLOC counter, not physical line counts. Verify with `.\.venv\Scripts\python.exe -c "import sys; sys.path.insert(0,'bin'); from file_length_gate import _count_lloc; ..."` before declaring debt.

### [2026-06-26] EasyOCR set as primary OCR for Hebrew-first project despite no Hebrew model
- **Mistake**: `_ocr_factory.get_engine` listed EasyOCR first in the engine candidate list. EasyOCR has NO Hebrew model (issues #363, #1334 closed unresolved; last release Sept 2024). For any Hebrew OCR request, EasyOCR was always excluded by `_supports_lang` and Tesseract was used ג€” but the ordering was misleading and wasted an availability probe on every Hebrew call.
- **Root cause**: The factory was written assuming EasyOCR's "80+ languages" claim covered Hebrew. It does not. The `_supports_lang` guard caught it at runtime, but the conceptual ordering ("EasyOCR primary") was wrong and propagated to docstrings/SKILL.md.
- **Rule**: For any Hebrew-first project, Tesseract must be the default primary OCR engine. EasyOCR should only be primary for LTR-only language requests. Always verify language support claims against the actual model list, not marketing numbers.
- **Resolution (2026-07-03)**: EasyOCR removed entirely. Sentinel is now Tesseract-only (single backend). EasyOCR's PyTorch dependency (~2GB) competed with the LLM for the 6GB VRAM budget, and Tesseract already handles both Hebrew and LTR langs on CPU. No LTR fallback justification remained.

### [2026-06-26] deep-translator Google endpoint is unofficial and can break silently
- **Mistake**: The sole translation path (`_robust_translate` in file_analyst, and `DeepTranslatorBackend` in translator-skill) depended on `deep-translator` wrapping Google Translate's free web endpoint. This is unofficial, rate-limited, and can break without notice.
- **Root cause**: No offline alternative was wired in. The translator-skill orchestrator had a 3-backend fallback chain (MyMemory ג†’ deep-translator ג†’ LibreTranslate) but all three are online and depend on third-party endpoints.
- **Rule**: For critical translation paths, always wire an offline-capable backend (opus-mt/CTranslate2 for enג†”he) as primary. Online backends are fallbacks, not the foundation. The orchestrator must treat `NotImplementedError` (unsupported pair) differently from `Exception` (backend failure) ג€” don't trip the circuit breaker for unsupported pairs.

### [2026-06-16] memory_summarizer used inferior JSON parsing while robust utilities existed elsewhere
- **Mistake**: `memory_summarizer._safe_parse_json` reimplemented its own markdown-strip + trailing-comma logic, but lacked the array-unwrap, brace-repair, and list-to-dict guards already proven in `services/agent/_helpers.py` and `_json_utils.py`. An 8052-char Hebrew LLM response wrapped in `[{...}]` failed parse, causing the daily summarization job to silently drop a full day of user memory.
- **Root cause**: Code drift. The agent layer had iterated its JSON defenses (brace_depth, array unwrap, scalar guard, list extraction) across multiple bug fixes, but the memory summarizer ג€” a separate consumer of the same 4B model ג€” kept its original naive parser.
- **Rule**: Before writing or fixing JSON parsing for LLM output, grep the codebase for existing `_json_utils`, `_helpers.py`, or `parse_react_response` utilities. Reuse the battle-tested stack; never maintain parallel, inferior parsers. If a utility is internal (`_`-prefixed) but stable, import it rather than duplicate.

### [2026-05-29] Claimed "no venv / no pytest" when .venv existed
- **Mistake**: Reported that no project venv was found and pytest was unavailable, skipping the test run. A `.venv` with `pytest.exe` existed at the repo root.
- **Root cause**: Used `find_by_name`, which respects `.gitignore` and silently skips ignored dirs like `.venv`. Concluded absence from a filtered search.
- **Rule**: Never conclude "file/dir does not exist" from `find_by_name` alone ג€” it ignores gitignored paths. To confirm tooling/venv presence, run `Get-ChildItem -Force` on the root and check `.venv\Scripts\`. Always prefer the project venv interpreter (`.venv\Scripts\python.exe`) for tests/imports.

### [2026-06-28] Stale context ג€” presented 7 orphaned capabilities when 5 were already wired
- **Mistake**: Presented a list of 7 "orphaned" capabilities needing wiring. In reality, 5 were already committed and in production (commits `cdb75df` Batch 1, `55087c7` Batch 2). Only #5 (extract_credentials) and #7 (recall_decayed_score) were genuinely unwired.
- **Root cause**: Session summary listed edited files but not commit outcomes. I regenerated the "orphan list" from a stale mental model instead of `git log --oneline | grep -i "wire\|orphan\|batch"` to verify what was already done.
- **Rule**: Before presenting any "remaining work" list, run `git log --oneline -20` and cross-reference each item against actual commits. The commit history is the source of truth for "what's done" ג€” not the conversation summary. Treat summaries as hints, not state.

---

## Lessons

<!-- New lessons added below -->

### [2026-07-09] Cloud-era LLM optimization recommendations hallucinated for Edge AI project
- **Mistake**: Audit subagents recommended A-5 (LLM background job batching), A-6 (cache embeddings), A-7 (speculative pre-compute) based on cloud/enterprise best practices. All three are over-engineering that contradicts the hardware constraints.
- **Root cause**: Subagents applied generic Microservices/Enterprise patterns without checking the deployment context: 6GB VRAM, single local model (KoboldCpp), serial execution (batch_size=1 is optimal for first-token latency), existing SQLite+FTS5+Vectorlite embedding store.
- **Rule**: Before accepting any LLM optimization recommendation, verify it against the hardware envelope: (1) Edge AI with ≤8GB VRAM → batch_size=1 is optimal, no batching layer; (2) local model → no network latency to hide with pre-compute; (3) check existing storage layers before recommending new cache tiers. Cloud patterns (batching, speculative pre-compute, multi-tier cache) are anti-patterns on edge hardware — they waste VRAM and add complexity for zero gain.

### [2026-07-07] Connection-storm IoC counted benign self-whitelisted connections as the anomaly signal (self-DoS)
- **Mistake**: `_collect_suspicious_net` returns `self_filtered` ג€” the count of Sentinelג†’KoboldCpp connections that were classified as benign and filtered OUT of `suspicious_net`. This count was stored as `snapshot["kobold_connections"]` and the storm detector fired `force_open()` when it exceeded 10. With 11-15 normal pool connections, the circuit breaker oscillated `FORCED OPEN ג†’ CLOSED ג†’ FORCED OPEN` every ~60s ג€” a self-DoS that disabled the LLM bridge on every other cycle. The 90s warmup grace (commit a21423a) was a band-aid that only delayed the first trip.
- **Root cause**: Category error. Self-whitelisted connections are benign by definition ג€” counting them as the storm signal inverts the whitelist's semantics. The original storm root cause (per-call `httpx.AsyncClient` creation in `_fetch_koboldcpp_perf`) was already fixed by the shared `_custom_http_client` (`max_connections=5`), making the IoC layer both redundant and harmful.
- **Rule**: Never use a "filtered/benign" count as an anomaly signal ג€” that inverts the filter's semantics. Anomaly detectors must count what survives filtering (the genuinely suspicious set), not what was suppressed. When a root cause is fixed at the source (shared resource pool), remove downstream band-aids instead of stacking grace periods on top. A warmup grace that only delays the first trip is a symptom, not a fix ג€” investigate why the detector trips in steady state.

### [2026-06-30] pip-audit warnings were left as non-blocking, allowing vulnerable dependencies to persist
- **Mistake**: `bin/lint-gate.py` reported 5 known vulnerabilities (deep-translator PYSEC-2022-252, pytest CVE-2025-71176, torch CVE-2025-3000, transformers PYSEC-2025-217 / CVE-2026-1839) as a warning only. The gate returned `PASS (warning)` instead of failing, so the dependency debt was visible but never forced remediation.
- **Root cause**: The gate had `block = False` with a comment saying to flip it after deps are upgraded. That upgrade was deferred indefinitely, turning the audit into a silent dashboard that accumulated supply-chain risk.
- **Rule**: After a vulnerability is acknowledged, set a concrete remediation window. Remove compromised packages that have no safe version (deep-translator had no fixed release), bump packages with fixes (pytest ג†’ 9.0.3+, torch ג†’ 2.12.1+, torchvision ג†’ 0.27.1+), and remove unused/stray packages that drag in vulnerable transitive deps (magic-pdf was unused but pulled transformers). Once clean, flip the gate to `block = True` and re-run the full lint-gate plus targeted tests to prove no regressions. pip-audit warnings are not a steady state.

### [2026-06-20] Tool Ranker ג€” Time Decay for monotonic penalty (FUTURE)
- **Issue**: The Adaptive Tool Ranker uses linear penalty: `score -= failures * 10`. A tool that crashed 5x due to an external server outage stays at score=50 forever, even after the server recovers. No recovery path.
- **Root cause**: `get_tool_stats()` returns `COUNT(*) + SUM(hit_count)` ג€” aggregate counts with no timestamp weighting. Old failures weigh the same as recent ones.
- **Future fix**: Exponential decay scoring:
  ```
  score = 100 - ־£(failure_i * decay_factor(age_i))
  decay_factor = exp(-־» * hours_since_failure)
  ־» = 0.01  (half-life ~69h ג‰ˆ 3 days)
  ```
  Implementation: `get_tool_stats()` needs to return per-failure timestamps (or compute decay in SQL with `julianday('now') - julianday(timestamp)`). `_tool_ranker.py` applies decay per-failure instead of flat count.
- **Rule**: Any penalty system that accumulates over time MUST have a decay/recovery mechanism. Linear accumulation without decay creates permanent "ghost penalties" that outlive the root cause. Design the decay curve BEFORE deploying the penalty.

### [2026-06-20] Double embedding ג€” semantic search called twice on same query
- **Mistake**: `_rank_tools_by_history()` and `_inject_memory()` both called `search_lessons(user_question)` independently. Each call invokes `embed_texts()` (20-100ms). Same vector computed twice.
- **Root cause**: Two functions in the same pipeline (_select_tools ג†’ _inject_memory) independently discovered they needed lessons, without sharing the result.
- **Fix**: Pre-fetch lessons once in `_build_agent_context()`, pass as `prefetched_lessons` to both functions.
- **Rule**: When two functions in the same pipeline consume the same expensive resource (embedding, DB query, API call), hoist the call to the orchestrator and pass results down. Profile for hidden latency ג€” "0ms" claims require verifying that no I/O is hidden behind a function call.

### [2026-06-20] Normalized error signatures ג€” dynamic data breaks GROUP BY
- **Mistake (prevented)**: Initial plan was to pass `str(exception)` directly to `store_lesson()`. Exceptions like `MemoryError at 0x7FFA...` or `Timeout on PID 1452` contain dynamic data that would make every crash look unique to `GROUP BY tool_name`.
- **Root cause**: Exception messages include runtime state (memory addresses, PIDs, timestamps) that varies per invocation.
- **Fix**: `_normalize_error_signature()` extracts only the exception TYPE: `SYSTEM_CRASH_MemoryError`, `TIMEOUT`, `LOGICAL_ERROR`, `SECURITY_VIOLATION`. Stable strings enable proper aggregation.
- **Rule**: Any string that will be used for GROUP BY, dedup, or counting MUST be normalized to remove dynamic data. Extract the signal (error class), discard the noise (runtime state). Test with 3 different exception instances of the same type ג€” they must produce the same signature.

### [2026-06-20] Interceptor ג€” premature final_answer without tool data in DAG
- **Mistake**: The subtask interceptor marked subtasks as "done" when the LLM called `final_answer` without executing any tool. Hallucinated text passed to downstream dependencies as if it were real data.
- **Root cause**: The interceptor checked `current_subtask_idx < len(subtasks)` but never verified that actual tool data existed (`_last_raw_tool_result` or `_tools_used`). The 4B model's tendency to call `final_answer` early was treated as completion.
- **Fix**: Added `_has_tool_data()` guard ג€” subtask only marked done if a tool was actually called AND returned non-empty data. Otherwise the subtask is reset and the LLM is nudged to call the right tool.
- **Rule**: Never trust `final_answer` as a completion signal without verifying tool execution. The 4B model will hallucinate completion to escape cognitive load. Completion = tool executed + data returned + answer references that data.

### [2026-06-16] KoboldCpp + 4B model cannot reliably handle JSON response_format
- **Mistake**: The Critic node (`_helpers.py`) and Tool Selection Review used `response_format={"type": "json_object"}` expecting structured JSON from the 4B model. The model consistently returned garbage wrapped in JSON arrays.
- **Root cause** (discovered via direct KoboldCpp API testing): KoboldCpp applies a grammar enforcement when `response_format` is set. The 4B model cannot generate valid nested JSON objects, so it compensates by wrapping its natural-language output in a JSON string array.
- **Fix (Hotfix #37, 16.06)**: Removed `response_format` from Critic and Tool-Review. Changed prompts to plain-text (`PASS:`, `FAIL:`, `SCORE:`). Replaced JSON parsers with simple regex.
- **Fix (Hotfix #38, 17.06)**: Removed `json_schema`/`strict=True` from core `agent_step()` ReAct loop. Converted system prompt to textual ReAct format (`Thought:`, `Action:`, `Action Input:`). Rewrote `_react_parser.py` with 3-tier parser (textual ג†’ legacy JSON ג†’ fallback).
- **Rule**: **For ALL LLM nodes on KoboldCpp 4B: NEVER use `response_format` or `json_schema`. Always use plain-text regex parsing.** Zero exceptions. The `json_schema`/`strict=True` path is dead ג€” completely migrated to plain-text.

### [2026-06-13] Ratchet protocol ג€” never lower threshold below proven CC
- **Mistake**: After refactoring `_helpers.py` (589 lines ג†’ 447 ג†’ 354), the cyclomatic complexity threshold was left at the original value, allowing regression.
- **Root cause**: No formal ratchet mechanism. Refactors reduced complexity but the gate threshold didn't tighten to lock in the gain.
- **Fix**: Implemented ratchet protocol in `.xenon.yml` and `setup.cfg`. Threshold can only tighten, never loosen.
- **Rule**: After ANY refactor that reduces complexity, immediately lower the gate threshold to the new proven max. The ratchet only tightens. Never lower the threshold below the proven CC.

### [2026-06-13] SRP refactor ג€” _helpers.py was 589 lines with mixed responsibilities
- **Mistake**: `_helpers.py` accumulated critic, planner, interceptor, and reactor logic. Single file, 589 lines, multiple responsibilities.
- **Root cause**: Organic growth without extraction boundaries. Each new feature was added to the "helpers" file.
- **Fix**: Split into `_agent_critic.py`, `_agent_planner.py`, `_agent_interceptor.py`, `_agent_reactor.py`. Each < 300 lines, single responsibility.
- **Rule**: When a file exceeds 300 lines, identify the extraction boundary and split. Never let a "helpers" file accumulate multiple responsibilities. AGENTS.md enforces 300-line max.

### [2026-06-13] Import cycle ג€” agent ג†’ telegram ג†’ agent
- **Mistake**: `services/agent/_helpers.py` imported `services.telegram.channel` for sending messages. `telegram.channel` imported `services.agent` for routing. Circular import.
- **Root cause**: No architectural layering. Agent and Telegram were peers, not layers.
- **Fix**: Extracted `telegram_channel` as a separate module. Agent imports telegram_channel (UI layer ג†’ agent layer is forbidden). Import-linter contract enforces this.
- **Rule**: Define architectural layers BEFORE writing cross-layer code. Agent must never import Telegram UI. Use import-linter contracts to enforce at CI time.

### [2026-06-10] Staleness warning ג€” model reused stale memory instead of calling live tool
- **Mistake**: The 4B model answered "CPU is at 45%" from conversation history instead of calling `get_system_snapshot`. The user got stale data presented as current.
- **Root cause**: No staleness signal in the prompt. The model couldn't distinguish "this was from a prior turn" vs "this is current".
- **Fix**: Added `<staleness_warning>` directive injected when live-data tools are active AND history exists. Wraps the user question with a warning that prior-turn metrics are STALE.
- **Rule**: When the model has access to both memory and live-data tools, ALWAYS inject a staleness directive. The 4B model will prefer the cheaper path (memory) unless explicitly forbidden.

### [2026-06-10] Tool output truncation ג€” last tool output must be protected
- **Mistake**: `_trim_messages` truncated ALL tool outputs uniformly under pressure. The last tool output got shrunk to 125 chars, causing the LLM to re-request the same tool (infinite loop).
- **Root cause**: No distinction between "old tool output" (can shrink) and "last tool output" (must preserve for the current reasoning step).
- **Fix**: `_LAST_TOOL_FLOOR = 1000` ג€” the last tool output is never shrunk below 1000 chars. Older outputs shrink progressively (500 ג†’ 250 ג†’ 125).
- **Rule**: The most recent tool output is the anchor for the current reasoning step. Protect it from aggressive truncation. Older outputs are disposable context.

### [2026-06-10] Emergency Reserve ג€” model called tools after budget exhaustion
- **Mistake**: The 4B model kept calling tools even after the token budget was exhausted, producing truncated/garbled output.
- **Root cause**: No hard stop signal. The model didn't know the budget was gone.
- **Fix**: Emergency Reserve system message injected at step N when budget is low: "FORBIDDEN from using any tool except final_answer". Protected by `_mid_system_msgs` in trim.
- **Rule**: When the token budget is near exhaustion, inject a hard constraint that forces termination. The 4B model will not self-terminate without an explicit signal.

### [2026-06-08] ReAct parser ג€” 3-tier fallback for 4B model output
- **Mistake**: The ReAct parser expected strict `Thought: ... Action: ... Action Input: {...}` format. The 4B model frequently deviated (missing Action Input, extra text, JSON instead of plain text).
- **Root cause**: The 4B model is not reliable enough for strict format adherence. Single-tier parsing failed on ~15% of steps.
- **Fix**: 3-tier parser: (1) textual regex ג†’ (2) legacy JSON ג†’ (3) fallback heuristic. Each tier catches what the previous missed.
- **Rule**: Never rely on a single parsing strategy for 4B model output. Always have a fallback chain. The model WILL deviate from the expected format.

### [2026-06-08] Context window blowout ג€” 4B model has 16K context, not 128K
- **Mistake**: Assumed the 4B model had a large context window. Injected full conversation history + tool outputs. Hit context_length_exceeded at ~16K tokens.
- **Root cause**: No token budget tracking. The 4B model (Qwen2.5-3B-Instruct via KoboldCpp) has a 16K context window, not 128K.
- **Fix**: `LLM_AGENT_TRIM_CHARS = int(LLM_CONTEXT_WINDOW * 0.75)` = 12,288 chars. `_trim_messages` enforces this. Emergency overflow trim for 400 errors.
- **Rule**: Know your model's context window BEFORE injecting history. Track token budget. Always have an emergency trim for context_length_exceeded errors.

### [2026-06-08] Bypass routing ג€” 4B model cannot handle multi-intent queries
- **Mistake**: Routed "translate and summarize" to the LLM. The 4B model did one task and ignored the other.
- **Root cause**: The 4B model cannot decompose multi-intent queries reliably. It picks one intent and drops the rest.
- **Fix**: Bypass routing detects multi-intent queries and routes to specialized bypass handlers (translation, summarization, currency, weather, etc.) that don't need the LLM.
- **Rule**: For 4B models, detect multi-intent queries early and route to deterministic bypass handlers. Don't expect the 4B model to decompose ג€” it won't.

### [2026-06-06] PID recycling ג€” kill_process killed the wrong process
- **Mistake**: `kill_process` matched by PID only. The original process exited, the PID was recycled, and a new innocent process was killed.
- **Root cause**: No PID recycling guard. PIDs are not unique across time.
- **Fix**: Composite target `pid|name` + PID recycling guard (verify process name matches before kill).
- **Rule**: Never kill by PID alone. Always verify the process identity (name, cmdline, start time) before killing. PIDs are recycled by the OS.

### [2026-06-06] TTP score >= 85 auto-queues kill_process
- **Mistake**: High TTP score detected but no automated response. The threat was logged but not acted on.
- **Root cause**: No kill threshold. TTP score was informational only.
- **Fix**: TTP score >= 85 auto-queues `kill_process` with an "Approve Kill" button in Telegram. Human-in-the-loop for safety.
- **Rule**: Threat scores must have action thresholds. A score with no action is just a log entry. Define the threshold and the automated response BEFORE deploying the scorer.

### [2026-06-06] PowerShell regex ג€” .exe suffix evasion
- **Mistake**: The PowerShell detection regex required `.exe` suffix. Malware using `powershell` (no suffix) evaded detection.
- **Root cause**: Regex was too strict. Windows allows executing `powershell` without the `.exe` suffix.
- **Fix**: Regex now matches with or without `.exe` suffix.
- **Rule**: Detection regexes must account for execution variants. Test with evasion cases (no suffix, full path, relative path, environment variables).

### [2026-06-06] YARA scanning ג€” 5 sentinel rules + file_analyst scan action
- **Mistake**: No YARA scanning. File analysis was heuristic-only.
- **Root cause**: YARA wasn't integrated.
- **Fix**: YARA scanning engine with 5 sentinel rules. `file_analyst` scan action triggers YARA on file drop.
- **Rule**: Heuristic detection is not enough. YARA rules provide signature-based detection that catches known malware families. Layer heuristic + signature detection.

### [2026-06-06] FIM watch paths ג€” SYSTEM user has no Downloads
- **Mistake**: FIM watched `~/Downloads` by default. When running as SYSTEM (NSSM service), `USERPROFILE` is absent and `~/Downloads` doesn't exist.
- **Root cause**: Hardcoded user paths. No fallback for service accounts.
- **Fix**: `FIM_WATCH_PATHS` env var override. Lazy-resolve watch paths at runtime, not at import time.
- **Rule**: Never hardcode user paths. Always support env var overrides. Test with service accounts (SYSTEM, LocalService) that have no user profile.

### [2026-06-06] FIM handoff ג€” watchdogג†’YARA with thread-safe handoff
- **Mistake**: Watchdog and YARA ran in the same thread. Watchdog blocked on YARA scan, missing file events.
- **Root cause**: No thread separation. I/O-bound (watchdog) and CPU-bound (YARA) work mixed.
- **Fix**: Thread-safe handoff queue. Watchdog enqueues, YARA worker dequeues. 3-layer filters + exponential backoff.
- **Rule**: Separate I/O-bound and CPU-bound work into different threads. Use a thread-safe queue for handoff. Never block the event loop with CPU-bound work.

### [2026-06-30] Token Bloat in batch LLM jobs ג€” GROUP BY + COUNT before injection
- **Mistake**: Planned to feed raw error_lessons rows to LLM for weekly reflection. 400 identical errors ג†’ 400 lines ג†’ context window explosion.
- **Root cause**: No aggregation layer between SQL and LLM. Raw rows = O(n) tokens, aggregated = O(unique patterns).
- **Rule**: Before injecting DB data into an LLM prompt, always GROUP BY + COUNT in SQL. Dedup at the query layer. LIMIT unique patterns (15 max). Keep total input <1000 tokens for 4B models.

### [2026-06-30] Batch jobs don't belong in startup/ ג€” SRP for folder structure
- **Mistake**: Initially planned `services/startup/_reflection.py` for the weekly reflection job.
- **Root cause**: Confused bootstrap (runs once at init) with scheduled batch jobs (run on cron). startup/ is for initialization, not recurring tasks.
- **Rule**: Batch/cron jobs go in `services/<domain>_agent.py` or `services/cron/`, NOT `services/startup/`. Startup is bootstrap-only. Single Responsibility applies to folder structure, not just classes.

### [2026-06-30] Weekly Reflection ג€” Critic Node
*   Logical errors occurred twice in the `skill_report-maker` tool on 2026-06-24, indicating a need for stricter input validation before tool invocation.
*   Despite zero recorded LLM calls and latency in the telemetry, the presence of tool failures suggests the system may be failing silently or the metrics are not capturing the full scope of execution failures.
*   The low average threat score (0.2) combined with only 3 high-risk dispatches out of 7 total suggests a potential gap in threat detection sensitivity or false negative handling.

*   ׳×׳׳™׳“ ׳‘׳•׳“׳§ ׳׳× ׳₪׳׳˜ ׳”-JSON ׳׳₪׳ ׳™ ׳§׳¨׳™׳׳” ׳׳›׳׳™ ׳›׳“׳™ ׳׳׳ ׳•׳¢ ׳©׳’׳™׳׳•׳× ׳׳•׳’׳™׳•׳×.
*   ׳×׳׳™׳“ ׳×׳‘׳“׳•׳§ ׳׳× ׳×׳•׳¦׳׳•׳× ׳”׳—׳™׳₪׳•׳© ׳׳₪׳ ׳™ ׳©׳׳™׳—׳× ׳”׳•׳“׳¢׳” ׳›׳“׳™ ׳׳׳ ׳•׳¢ ׳”׳׳—׳™׳¦׳•׳× ׳©׳’׳•׳™׳•׳×.

### [2026-05-29] Claimed "no venv / no pytest" when .venv existed
- **Mistake**: Reported that no project venv was found and pytest was unavailable, skipping the test run. A .venv with pytest.exe existed at the repo root.
- **Root cause**: Used find_by_name, which respects .gitignore and silently skips ignored dirs like .venv. Concluded absence from a filtered search.
- **Rule**: Never conclude "file/dir does not exist" from find_by_name alone ג€” it ignores gitignored paths. To confirm tooling/venv presence, run Get-ChildItem -Force on the root and check .venv\Scripts\. Always prefer the project venv interpreter (.venv\Scripts\python.exe) for tests/imports.

---

### L7: Module-level cache dir froze env at import time ג†’ test isolation failure
- **Mistake**: `test_vt_rate_limit.py::test_429_returns_fallback_flag` failed when run after `test_abuse_feeds.py` (passed in isolation). Reported coverage as 66.64% from a stale 5-hour-old `coverage.json`.
- **Root cause**: `_utils.py` bound `_CACHE_DIR = Path(os.getenv("SENTINEL_STATE_DIR") or ...) / "intel_cache"` at import time. `test_abuse_feeds` imported `osint_gatherer` first (with the real state dir), so `_utils` cached that path. The VT test's `monkeypatch.setenv` + `importlib.reload(osint_gatherer)` did NOT reload `_utils`, so `cache_get("virustotal", ...)` read the real cache, returned a stale `{"available": True}` before the mocked `requests.get` was ever called. Separately, the coverage gate reused a 5h-old `coverage.json` (10-min cache window) instead of re-running pytest.
- **Rule**: Never bind env-derived paths at module top-level if the env can change at runtime (tests, redeployment). Make them lazy via a `_resolve_dir()` function called inside `get`/`set`. When a test passes in isolation but fails in a full run, suspect module-level state frozen at import. When reporting coverage %, check `coverage.json` mtime first ג€” if older than the last code change, force `--fresh`.
- **Fix**: Replaced `_CACHE_DIR` module constant with `_cache_dir()` lazy resolver in `skills/intel-skill/scripts/_utils.py`; removed the now-broken `_CACHE_DIR` re-export from `intel.py`.

---

## 2026-07-03 ג€” Risk-Based Coverage Sprint

### L1: coverage_gate.py --regenerate hang
- **Mistake**: `bin/coverage_gate.py --regenerate` hung for 5+ minutes, appeared stuck.
- **Root cause**: `_regenerate_baseline()` called `_run_pytest_cov(force=True)` ג€” always re-ran the full 200+ test suite, ignoring the fresh `coverage.json` that `lint-gate` had just produced.
- **Rule**: Never force-cache-bypass in a regenerate command when another gate already produces the artifact. Cache reuse = seconds vs minutes. `--regenerate` now reuses cached coverage.json (<10 min); `--fresh` forces re-run.

### L2: Test assertions must not embed the hallucinated entity in tool_data
- **Mistake**: 5 entity-audit tests failed ג€” `_audit_entity_claims` returned `[]` when the test expected flagged entities.
- **Root cause**: Tests wrote `tool_data = "no 12847 here"` ג€” the string "12847" IS in tool_data, so the audit correctly passes (entity is grounded). The word "no" doesn't matter to a substring check.
- **Rule**: When testing hallucination detection, `tool_data` must NOT contain the entity string anywhere. Use neutral text like `"scan complete: baseline only"`.

### L3: Module-level test state leaks across files (B6 lockout_log)
- **Mistake**: `test_web_c2_rce_hardening.py` 2FA tests failed with `OTPRateLimitError: lockout cooldown` ג€” but those tests didn't trigger a lockout.
- **Root cause**: B6 fix added `_lockout_log` module-level list in `two_factor.py`. The `_clear_2fa_state` fixture in the web_c2 test file cleared `_challenges` + `_otp_generation_log` but NOT `_lockout_log`. A prior test's lockout entry contaminated subsequent tests.
- **Rule**: When adding new module-level mutable state to a security module, EVERY test file with a clearing fixture for that module must clear the new state too. Audit all `*_state`/`*_clear` fixtures when adding state.

### L4: Per-file 95% target is wrong granularity for multi-purpose files
- **Mistake**: Only 1/9 modules hit 95% file-level coverage despite comprehensive security tests.
- **Root cause**: Files like `system_intel.py` (121 stmts) contain both security-critical (`terminate_process`, 24 lines) AND non-security functions (process listing, network adapters, event logs ג€” 97 lines). File-level 95% requires covering non-security code.
- **Rule**: For risk-based coverage, target FUNCTION-level or BRANCH-level coverage on security-critical functions, not file-level. File-level 95% on multi-purpose files is the wrong metric ג€” it forces testing irrelevant code.

### L5: Subagents can't run exec ג€” always verify in parent
- **Mistake**: All 4 parallel subagents reported "unable to run pytest" and submitted unverified tests.
- **Root cause**: Background subagents auto-deny exec tool permissions. They wrote tests via code review only.
- **Rule**: After parallel subagent test-writing, the parent MUST run the tests. Expect 5-15% test failures from mock-path mismatches, assertion errors, and state-leak issues that only surface at runtime.

### L6: Overwrote lessons.md instead of appending
- **Mistake**: Used `write` tool on `tasks/lessons.md` which contained 212 lines of historical lessons, replacing all content with 29 new lines.
- **Root cause**: Checked file was "empty" via `Get-Content | Select-Object -Last 40` which returned no visible output ג€” but the file had 212 lines. The PowerShell output was empty due to encoding/display, not actual emptiness.
- **Rule**: Before using `write` on an existing file, verify its line count with `(Get-Content file).Count` or `read` the file first. Use `edit` to append to existing content, never `write` to overwrite documentation files.

### [2026-07-04] memory_summarizer still passed response_format=json_object after the 4B-KoboldCpp finding
- **Mistake**: `services/memory_summarizer.py:152` passed `response_format={"type": "json_object"}` with the comment "ignored if unsupported". The 4B model on KoboldCpp deterministically collapsed to `not json at all {{{` (6 identical 19-byte failures on 2026-07-04), silently dropping a full day of user memory each run.
- **Root cause**: The team had already proven (commit removing JSON-schema from `agent_step`, documented in `services/llm_bridge/completion.py:195-197`) that KoboldCpp honors `response_format` and breaks the 4B. A regression guard (`tests/test_planner_smoke.py::test_decompose_task_no_response_format`) was added for the Planner. The memory_summarizer ג€” a separate consumer of the same 4B ג€” was missed in that sweep.
- **Rule**: Any LLM call site that passes `response_format={"type": "json_object"}` (or any grammar-enforcement kwarg) to the 4B/KoboldCpp bridge is a latent bug. Grep for `response_format` across `services/` before considering JSON-structured output wired. The robust JSON parser (`_safe_parse_json` / `_json_utils`) is the correct defense, not server-side grammar enforcement. A regression guard now exists for memory_summarizer mirroring the Planner one.

### [2026-07-05] conftest stubbed embed but not complete ג€” tests hit live KoboldCpp
- **Mistake**: `tests/conftest.py` had an autouse `stub_llm_embedding` fixture that mocked `LLMBridge.embed`, but NO equivalent stub for `LLMBridge.complete`. Any test calling `run_daily_summarization` / `agent_step` / `analyze_data` without its own mock would call the live KoboldCpp server at 127.0.0.1:5001 with a 240s timeout, hanging the event loop, polluting the real DB, and writing `memory_summarizer_fail_*.txt` artifacts to `logs/`.
- **Root cause**: The conftest was written when only embedding was used in tests. As more services gained LLM completion calls (memory_summarizer, monitor_analyzer, agent core), the gap was never closed. The `test_skill_smoke_all` and `test_telegram_poll_retry` hangs were symptoms ג€” the real blast radius was any unmocked `complete()` caller.
- **Rule**: Every external-network entry point (LLM `complete`, `embed`, HTTP APIs, subprocess) MUST have an autouse conftest stub that returns deterministic output by default. Tests that need real behavior override via their own `patch.object` (which replaces the class, taking precedence). The stub must defer to the original implementation when the test injects its own `_client` MagicMock, so context-overflow / error-path tests still work. Integration tests that genuinely need live infra are marked via `pytest_collection_modifyitems` (filename frozenset in conftest), NOT per-file `pytestmark` lines that inflate LLOC and trip the file-length ratchet.

### [2026-07-06] Hunt path bypassed every network filter the alert path applied
- **Mistake**: The threat hunter (`services/threat_hunter.py::_gather_context`) injected raw `snapshot["suspicious_net"]` lines into the LLM prompt and into `enrich_iocs_from_context`, bypassing the 5-layer suppression chain that `SnapshotDiffer._diff_connections` already applied (CDN CIDR, self-process, behavioral allowlist, learned baseline, intel whitelist). Result: routine Windowsג†’Azure telemetry (svchost ג†’ 13.69.x.x) reached the LLM, which hallucinated "Lateral Movement / Defense Evasion / Privilege Escalation" and dispatched a High-Risk alert.
- **Root cause**: Two detection paths (alert differ vs. proactive hunt) were written independently. The differ accumulated filters over sprints (Phase 7 behavioral, Phase 8 learned baseline, Phase 9 intel whitelist) but the hunt path was never updated to mirror them. There was no SSOT ג€” the filter chain was inlined into the differ, so the hunt builder had no shared function to call.
- **Rule**: Any filter/whitelist chain applied on one ingestion path MUST be extracted into a shared module (SSOT) and called by every path that feeds the same data into the LLM. "The LLM cannot hallucinate about data it never sees" ג€” deterministic pre-filtering beats post-hoc Reflection/Critic gates. When adding a new consumption path for an existing data source, grep for the existing filter and reuse it; do not re-inline the logic. A separate lesson: trusted-ISP + verified-VT-clean cross-validation must override abuse-only scores on multi-tenant cloud IPs (AbuseIPDB mass-reporting is noise, not signal) ג€” the override must NOT be gated behind a `score < N` condition that the abuse score itself makes unreachable.

### [2026-07-06] ALTER TABLE ADD COLUMN with non-constant DEFAULT crashed startup
- **Mistake**: `services/metrics_db.py:103` used `ALTER TABLE net_baselines ADD COLUMN last_seen DATETIME DEFAULT CURRENT_TIMESTAMP`. SQLite forbids non-constant expressions (CURRENT_TIMESTAMP, datetime('now'), etc.) as column defaults in `ALTER TABLE ADD COLUMN` ג€” only `CREATE TABLE` allows them. The bot crashed on startup with `Cannot add a column with non-constant default`.
- **Root cause**: The migration was written assuming SQLite DEFAULT semantics match PostgreSQL. They don't for ALTER TABLE. The backfill (`UPDATE ... SET last_seen = first_seen`) already handled legacy rows, making the DEFAULT clause unnecessary.
- **Rule**: In SQLite migrations, `ALTER TABLE ADD COLUMN` only allows constant defaults (literals like `0`, `''`, `-1`). For non-constant defaults (CURRENT_TIMESTAMP, datetime('now')), add the column without a DEFAULT and backfill via UPDATE. Always test migrations against a fresh DB file before declaring done.

### [2026-07-07] Decentralized Swarm via MCP ג€” rejected as over-engineering without a use case
- **Mistake**: Investigated extending the local MCP server (port 11123, loopback-only) into a Decentralized Swarm / federated EDR across LAN peers. Deep analysis identified 12 gaps (G1-G12) and 3 critical risks (R1 lateral movement, R2 SSRF amplification, R3 provenance poisoning). The existing single-user Sentinel deployment has no load/capacity problem that federation solves.
- **Root cause**: The MCP server's `call_mcp(url, ...)` already accepts a remote URL parameter, and `/mcp/skill/<name>` was docstring-flagged for "external HTTP integrations" ג€” these forward-looking hooks invited speculation about a Swarm architecture without an actual multi-machine use case driving it.
- **Rule**: Do not pursue Decentralized Swarm / peer-to-peer federation of Sentinel. The attack surface multiplies ֳ—N (N LAN-exposed endpoints vs 1 loopback), adds 3 critical risks that don't exist today, and requires ~820 LOC + a CA/PKI + replicated audit store ג€” all for zero benefit on a single-user EDR that isn't capacity-bound. If a genuine multi-machine LAN coverage use case arises in the future, Phase 0 (bind 0.0.0.0 + mTLS + per-agent signed identity + revocation) is the non-negotiable minimum before any federation code. Until then, the loopback MCP + single Bearer token is sufficient. Re-opening this direction requires a concrete use case (N machines, named threat) ג€” not architectural curiosity.

### [2026-07-09] Session start without reading lessons.md ג€” skipped protocol
- **Mistake**: Began fixing `memory_summarizer` JSON parse failure (bot.log 02:31) without first reading `tasks/lessons.md` or invoking the `lessons-review` skill. Jumped straight into code changes, violating AGENTS.md ֲ§4 ("Session start: ALWAYS read tasks/lessons.md first") and global_rules ֲ§3 (Self-Improvement Loop).
- **Root cause**: The bug was visually obvious (truncated mid-string JSON) and the fix path was clear, so the protocol step was skipped as "unnecessary overhead." But the lessons file contained the directly-relevant [2026-06-16] entry about this exact module's JSON parsing ג€” which I only read after the user pointed out the protocol violation.
- **Rule**: At the start of ANY work session, invoke the `lessons-review` skill and read `tasks/lessons.md` BEFORE making any code changes ג€” even when the fix seems obvious. The lessons file may contain constraints or prior decisions that shape the correct approach. Protocol steps are not optional overhead; they exist because skipping them caused past mistakes.

### [2026-07-10] Weekly Reflection ג€” Critic Node
*   **Latency Degradation:** The average p95 latency of 21,679ms indicates severe performance bottlenecks, likely caused by excessive tool invocation overhead or inefficient query routing, which directly impacts user experience and operational throughput.
*   **Tool Overuse:** Despite zero tool errors, the high frequency of `scan_suspicious_procs` (3x) and `get_system_snapshot` (2x) suggests a lack of strategic filtering, leading to unnecessary computational load without proportional value in the current low-threat environment (Avg Threat Score: 0.23).
*   **Risk Discrepancy:** The low average threat score of 0.23 contrasts sharply with 3 high-risk dispatches (>0.8), indicating potential hallucinations in threat assessment logic or inconsistent scoring criteria that result in false positives during critical decision-making.

*   **׳”׳₪׳—׳×׳× ׳–׳׳ ׳™ ׳×׳’׳•׳‘׳”:** ׳™׳© ׳׳”׳₪׳—׳™׳× ׳׳× ׳׳¡׳₪׳¨ ׳”׳ ׳§׳¨׳׳™׳ ׳׳›׳׳™ (Tool Calls) ׳•׳׳©׳₪׳¨ ׳׳× ׳™׳¢׳™׳׳•׳× ׳”׳¨׳™׳¦׳•׳™ ׳›׳“׳™ ׳׳”׳•׳¨׳™׳“ ׳׳× ׳”-Latency ׳׳¨׳׳” ׳׳§׳‘׳™׳׳”.
*   **׳׳™׳׳•׳× ׳§׳¨׳™׳˜׳™ ׳׳₪׳ ׳™ ׳©׳׳™׳—׳”:** ׳›׳ ׳©׳™׳ ׳•׳™ ׳‘׳×׳™׳§׳•׳ ׳”-JSON ׳׳• ׳§׳¨׳™׳׳” ׳׳›׳׳™ ׳—׳™׳™׳‘ ׳׳¢׳‘׳•׳¨ ׳‘׳“׳™׳§׳× ׳¢׳§׳‘׳™׳•׳× (Consistency Check) ׳›׳“׳™ ׳׳׳ ׳•׳¢ ׳”׳•׳•׳׳•׳•׳¨׳¦׳™׳•׳× (Hallucinations) ׳‘׳׳¢׳¨׳›׳•׳× ׳§׳¨׳™׳˜׳™׳•׳×.



### [2026-07-15] DBPool released connections with open transactions — poisoned next acquirer
- **Mistake**: `DBPool.acquire()` returned connections to `_available` without clearing any open transaction. A caller that left a transaction open (forgot `commit`, or crashed mid-write) poisoned the next acquirer. `night_watchman.run_memory_compaction` issues a manual `BEGIN IMMEDIATE` and crashed with `sqlite3.OperationalError: cannot start a transaction within a transaction` (bot.log 05:00:12), rolling back the entire compaction batch and leaving 10 IDs un-archived.
- **Root cause**: The pool treated connections as stateless on release, but aiosqlite/sqlite3 connections carry transaction state. `in_transaction` was never checked at release time. Only `night_watchman` (the sole caller doing manual `BEGIN`) surfaced the bug — every other caller relies on aiosqlite's implicit transaction, so the dirty state was silent until an explicit `BEGIN` collided with it.
- **Rule**: Any connection pool that returns connections to a free list MUST clear transaction state on release — check `in_transaction` and `rollback()` (never `commit()`: uncommitted state is by definition not the caller's intent). This is pool hygiene, not a caller responsibility. A single dirty release corrupts every subsequent acquirer that uses explicit transactions.

### [2026-07-17] Weekly Reflection — Critic Node
*   **Latency Spike & Tool Overload:** The p95 latency of 28,665ms indicates severe performance degradation, likely caused by the high frequency of `sentinel_get_system_snapshot_full` calls (9x) combined with the lack of caching or parallelization, which directly impacts user experience despite zero tool errors.
*   **Low-Value Tool Usage:** The absence of any dispatches and a near-zero threat score suggest that the active tools (`scan_suspicious_procs`, `skill_intel-skill`) are either misconfigured, returning non-actionable data, or failing to trigger the necessary escalation logic, leading to a "silent" operation that misses potential threats.
*   **Risk of Hallucination via Inaction:** With zero high-risk dispatches and no tool errors, there is a high probability that the system is hallucinating safety by failing to recognize patterns or misinterpreting the output of `sentinel_get_system_snapshot_full`, resulting in false confidence rather than genuine threat detection.

*   **הפחתת זמני תגובה:** צריך להשתמש ב-Caching או ב-Async Processing לכלי `sentinel_get_system_snapshot_full` כדי להוריד את ה-latency מ-28 שניות לרמה קבלה.
*   **אימות לפני פעולה:** לפני כל שליחת הודעה (Dispatch) או ביצוע פעולה, חובה לבצע בדיקת תוצאה (Validation) וודאות ש-JSON מתאים לפני שמתקבלת החלטה.
