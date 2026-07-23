# Sentinel — Conceptual Repo

> **Engineering showcase window.** This repository contains *only* the planning
> documents (README + ARCHITECTURE) for the Sentinel project — a local-first
> security monitoring agent that runs a 4B-parameter LLM inside a **6 GB VRAM**
> budget on consumer hardware. No source code is shipped here; the design
> documents below describe how the hard resource constraints were solved.
>
> For the full architecture reference with Mermaid flow diagrams, see
> [`ARCHITECTURE.md`](./ARCHITECTURE.md).

---

## What Is Sentinel?

Sentinel is a **local-first security monitoring bot** for Windows. It watches
system metrics (CPU, RAM, disk, network), enriches alerts with on-device LLM
reasoning, and delivers findings via Telegram. The agent core uses a
**ReAct (Reason + Act) loop** with explicit FSM routing, **17 bypass handlers**
for fast-path deterministic queries, **hybrid semantic + keyword routing**, a
**15-skill engine**, and a 4-block initializer pipeline that collapses context
before the LLM ever sees a prompt.

| Property | Value |
|----------|-------|
| LLM | Qwen3.5-4B (Q4_K_S GGUF, ~2.1 GB weights) |
| Inference backend | KoboldCpp (OpenAI-compatible API, `127.0.0.1:5001`) |
| Context window | 16,384 tokens (capped from native 262K by VRAM) |
| Embeddings | E5-large-instruct (1024-dim) |
| Vector search | vectorlite HNSW (`m=16, ef_construction=200, ef_search=64`) |
| Database | SQLite WAL mode — 7 databases, 19 base + 3 virtual tables |
| Language | Python 3.12.2 (strict typing, Pydantic V2, fully async) |
| Interface | aiogram 3.x (Telegram) + aiohttp (LAN dashboard) |
| Scheduler | APScheduler — 15 jobs (13 recurring + 2 startup pulses) |
| Skills | 15 (crypto, intel, firewall, file_analyst, pcap-analyst, …) |
| Tools | 55 in registry (system=24, file=5, memory=3, security=8, mcp=15) |
| Bypass handlers | 17 (11 original + 6 intent-based Visibility Triad routers) |
| Tests | 132 test files, 4,031 automated tests (all gates passing, zero mypy errors) |

### Production Telemetry (empirical, from live deployment)

| Metric | Value | Source |
|--------|-------|--------|
| Continuous uptime | 23h (2026-07-08 19:32 → 2026-07-09 18:35) | `bot.log.1` — zero Traceback/MemoryError, graceful SIGINT restart only |
| Monitor cycles | 2,488 nominal snapshots | `bot.log.1` — "Nominal" log lines |
| Alerts dispatched | 12 (cpu_spike, all delivered to Telegram) | `bot.log.1` — AlertDispatch Sent count |
| Suppressed (dedup/noise) | 14 | `bot.log.1` — MonitorAI suppressed count |
| Production RAM | ~323 MB RSS (Sentinel daemon, 46 threads) | `psutil` on NSSM-managed PID |
| TPOT tracking | EMA (α=0.2), baseline-locked after 10 samples | `circuit_breaker.py` |
| Embedding latency | 0.69ms per query (cached) | `crud_search.py` benchmark |

---

## The Three Hard Problems — And How They Were Solved

Running a capable agentic LLM on a 6 GB GPU is an exercise in brutal
trade-offs. Three engineering problems dominate the design.

### 1. The 6 GB VRAM Constraint

Qwen3.5-4B natively supports a 262K-token context window. On 6 GB VRAM that is
a fantasy — the KV cache alone would consume the entire card. Sentinel solves
this with a **four-layer defense**:

| Layer | Mechanism | Constant |
|-------|-----------|----------|
| **Quantization** | Q4_K_S GGUF — weights compressed to ~2.1 GB | `Qwen3.5-4B-Q4_K_S.gguf` |
| **KV cache cap** | Context locked to 16K tokens with `quantkv q8_0` | `LLM_CONTEXT_WINDOW = 16384` |
| **Sliding-window trim** | Drops oldest assistant+tool pairs; protects system head, mid-conversation system messages, and the current-turn user anchor | `LLM_AGENT_TRIM_CHARS = 8192` (50% of window) |
| **Emergency overflow** | On server-confirmed `context_length_exceeded`, hard-trims tool outputs to 100+50 chars (older) / 1200+500 chars (most recent) | `_emergency_trim_for_overflow()` |

**Tool-output floors prevent re-request loops**: the last tool output is never
shrunk below 1,000 chars (`_LAST_TOOL_FLOOR`), and older outputs shrink
progressively 500 → 250 → 125 chars. Without this floor, the 4B model would
re-request the same tool indefinitely because the truncated output no longer
contained the data it needed.

**Concurrency is serialized**: an `asyncio.Semaphore(1)` around the LLM bridge
guarantees only one inference runs at a time — two concurrent 16K-context
prefills would OOM the card instantly. The HTTP client is capped at
`max_connections=5, max_keepalive=2`.

**The trimmer is anchor-aware.** A subtle bug (documented in
`tasks/lessons.md`) taught us that directives must be injected as
`role:"system"` (protected by the mid-system-message reserve), never blended
into the `role:"user"` anchor message. Under overflow, a blended
`"User question: {q}"` wrapper could be truncated *before* the question
portion — losing the actual query while preserving the instruction. The fix:
directives and the user question are now separate, individually-protected
messages.

### 2. The TPOT Circuit Breaker (Crash Prevention)

A 4B model on a 6 GB card does not fail gracefully under load — it *slows*,
then *hangs*, then *crashes the KoboldCpp process*. Sentinel detects the slow
phase and degrades *before* the crash using a **TPOT (Time Per Output Token)
Circuit Breaker** with four states:

| State | Accepts traffic? | Entry condition | Exit condition |
|-------|-------------------|-----------------|----------------|
| `CLOSED` | Yes | Normal | — |
| `DEGRADED` | Yes (throttle signal) | TPOT > baseline × **3.0** | TPOT < baseline × **1.5** (hysteresis) |
| `OPEN` | **No** | 3 consecutive failures | 30 s cooldown → `HALF_OPEN` |
| `HALF_OPEN` | Probe only | Cooldown elapsed | Success → `CLOSED`, Failure → `OPEN` |

**How TPOT is measured:**
```
tpot_ms = (latency_seconds / generated_tokens) × 1000
tpot_ema = 0.2 × tpot_ms + 0.8 × tpot_ema_prev      # EMA smoothing (α=0.2)
```
- The baseline is **not locked** until `LLM_BASELINE_SAMPLES = 10` successful
  calls — avoiding a panic threshold set by cold-start noise.
- Samples under `LLM_MIN_TOKENS_FOR_TPOT = 50` tokens are ignored (prefill
  dominates short generations, making TPOT noisy and meaningless).
- When available, the **real decode time** is fetched from KoboldCpp's
  `/api/extra/perf` endpoint and takes priority over the heuristic.

**What DEGRADED does to the agent:** When `LLMBridge.is_degraded()` returns
true, the FSM **skips the PLANNER node** (routes straight to EXECUTE with
bypass tools) and **skips the CRITIC node** (routes straight to FINALIZE with
the draft answer). This cuts LLM calls roughly in half during stress — enough
to keep the bot responsive without abandoning the user. The flag
`ctx._degraded_mode = True` propagates so downstream nodes know they are
operating on a reduced budget.

**Why hysteresis (3.0 in / 1.5 out):** Without hysteresis the breaker would
flap — entering DEGRADED on a single slow batch, exiting on the next fast one,
re-entering on the third. The 2× gap between entry and exit thresholds
guarantees the system has genuinely recovered before it lifts the throttle.

**Context overflow is NOT a failure.** A `ContextOverflowError` (detected by
markers like `"context_length"`, `"n_ctx"`, `"maximum context"`) is raised
*without* counting toward the 3-failure OPEN threshold. The caller is expected
to trim and retry — it is a recoverable condition, not a sick model.

### 3. Semantic Routing (Deterministic Intent + Context Collapse)

A 4B model is a *tool-selection liability*. Given 55 tools it will hallucinate
tool names, pick the wrong one, or chain three tools when one would do. Sentinel
solves this with a **three-stage deterministic pipeline** that runs *before*
the LLM sees the prompt:

```
User question
   │
   ▼
┌─────────────────────────────────────────────────────┐
│  STAGE 1 — Intent Routers (zero I/O, pure regex)     │
│  detect_intent() → ioc | cve | hash | yara |         │
│                    pcap | eml | file | process |     │
│                    general                            │
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│  STAGE 2 — Pre-Compute Enrichment (only if IOC)      │
│  extract IOCs → enrich via VT/AbuseIPDB (quota-      │
│  allocated) → inject as [PRE-COMPUTED HARD FACTS]    │
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│  STAGE 3 — Tool Visibility Filter (context collapse) │
│  filter_tools_by_intent() → hide irrelevant tools    │
│  Saves 200–600 tokens/turn                           │
└──────────────────────┬──────────────────────────────┘
                       ▼
                 LLM sees a prompt with:
                 • the right tools (5–10, not 55)
                 • hard facts already enriched
                 • a single intent to serve
```

**Intent routers** (`intent_routers.py`) are pure functions with no I/O. They
detect 8 intent types via regex + keyword co-occurrence. Priority order
matters: `IOC > CVE > hash > yara > pcap > eml > file > process`. Keyword
co-occurrence prevents false positives — a 32-char hex string alone is not a
hash query, but a hex string *plus* "malware"/"reputation"/"scan" is.

**Pre-compute enrichment** runs only when external IOCs are detected. It
extracts up to 10 IOCs per type (IP/domain/hash), enriches them with
VirusTotal + AbuseIPDB using a quota-allocation strategy reused from the
pre-hunt enricher, and injects the results as an immutable
`[PRE-COMPUTED HARD FACTS]` block into the system prompt. This prevents the
4B model from *hallucinating threat scores* — the facts are already in the
prompt, the LLM only has to reason over them.

**Tool visibility** collapses the 55-tool registry to the 5–10 the intent
actually needs. `general` queries hide OSINT tools (costly, niche). `osint`
intent hides system+security tools (except `osint_hunt`). `security` hides
osint+system. `system` hides osint+security. `final_answer` is always kept.
One tool — `analyze_cmdline` — is permanently hidden because it was absorbed
into engine-level enrichment (a lesson from the Tool Visibility Filter fix).

**The 17 bypass handlers** go further: for *deterministic* queries (CVE
lookup, YARA scan, process list, weather, currency, …) they skip the LLM
entirely. The chain of responsibility tries handlers in priority order; the
first match calls the tool/skill directly and returns the result verbatim.
Order is critical: CVE before intel (prevents `CVE-2024-3094` routing as an
IOC); intel/firewall before stock (prevents `8.8.8.8` matching a ticker
symbol). The Threat Hunter passes `allow_bypasses=False` to force the full
ReAct loop — you do *not* want a proactive hunt to short-circuit.

---

## Why It Works on 6 GB

The unifying principle: **move determinism out of the LLM and into Python.**

| Decision | LLM cost | Deterministic cost |
|----------|----------|---------------------|
| Which tool to call | 1 LLM round-trip (unreliable on 4B) | 0 — regex intent router |
| Is this IP malicious? | LLM hallucinates a score | 0 — VT/AbuseIPDB pre-compute |
| Which 55 tools to show? | LLM sees all 55, picks wrong | 0 — visibility filter → 5–10 |
| "What's the weather?" | LLM round-trip + tool call | 0 — bypass returns verbatim |
| Context overflow recovery | crash | 0 — emergency trim + retry |

Every row in that table is a token saved and a hallucination prevented. On a
70B cloud model these optimizations are nice-to-have. On a 4B model with 16K
context and 6 GB VRAM, they are the difference between a working agent and a
toy.

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3.12.2 (strict typing, Pydantic V2, async) |
| LLM | Qwen3.5-4B (Q4_K_S) via KoboldCpp (16K context, 6 GB VRAM) |
| Embeddings | E5-large-instruct (1024-dim) |
| Vector Search | vectorlite HNSW (`m=16, ef_construction=200`) |
| Database | SQLite (WAL mode, 7 databases, 19 base + 3 virtual tables) |
| Telegram | aiogram 3.x |
| Web Dashboard | aiohttp (Basic Auth, IP whitelist, rate-limited) |
| Scheduler | APScheduler (15 jobs) |
| Skills | 15 (+ `_shared` library) |
| Tools | 55 (system=24, file=5, memory=3, security=8, mcp=15) |
| FIM + YARA | watchdog Observer + YARA (5 rules, 15 dangerous extensions) |
| TTP Detection | cmdline_analyzer (regex) → mitre_mapper (14 techniques) |
| OCR | Tesseract 5.x (CPU-only, Hebrew + LTR) |
| Translation | opus-mt (offline) → MyMemory → deep-translator → LibreTranslate |
| Lint Gates | ruff, xenon, import-linter, vulture, mypy, bandit, file-length, pip-audit |

---

## Documentation

- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — System design with Mermaid flow
  diagrams: ReAct FSM, Bypass chain, TPOT Circuit Breaker state machine, and
  the async SQLite WAL database architecture.

---

## Design Philosophy

1. **Local-first.** No cloud API calls for reasoning. The model, embeddings,
   vector search, and all databases run on-device. Cloud is only for intel
   enrichment (VirusTotal, AbuseIPDB) and translation fallback.
2. **Determinism over LLM judgment.** Every decision that *can* be made with
   regex/keywords/SQL *is*. The LLM is reserved for reasoning that genuinely
   requires it — and even then, its output is audited (tool-claim audit,
   hallucination score cap, bidirectional contradiction check).
3. **Fail-soft, never crash.** Circuit breakers, emergency trims, graceful
   degradation, dead-letter queues, and a 4-state CB mean the bot degrades
   to "slower but still answering" rather than "dead."
4. **Closed-loop learning.** Tool failures → `error_memory` (cosine-deduped
   lessons) → `_tool_ranker` (7-day half-life decay) → circuit breaker. The
   agent gets better at picking tools without a single fine-tune.
5. **Hebrew-first.** OCR, translation, keyword routing, and prompt anchoring
   all treat Hebrew as the primary language. Cyber terminology stays English
   inside Hebrew reports (deterministic anchoring) to prevent the 4B model
   from translating "MITRE ATT&CK" into malformed Hebrew.
