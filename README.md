# Sentinel

Local-first threat detection agent for Windows. Runs a 4B-parameter LLM
on-device (KoboldCpp) for inference without cloud dependency. Monitors
system behavior, enriches alerts with on-device reasoning, and delivers
findings via Telegram. Includes behavioral TTP detection (MITRE ATT&CK),
file integrity monitoring (watchdog + YARA), credential leak hunting,
and an OSINT subsystem with a 5-tier search waterfall.

> **This is a research/portfolio project, not a supported security product.**
> See [What This Is Not](#what-this-is-not) below.

---

## What This Is Not

**This is not a commercial security product, an EDR replacement, or
production-grade defense tooling.** It is a personal research project
exploring local-first LLM-driven threat detection on consumer hardware.

- It is **not supported** — no warranty, no maintenance guarantee, no SLA.
- It is **not a substitute** for professional EDR/XDR/AV solutions.
- It has **not been independently audited** or penetration-tested.
- The LLM (4B parameters) is **not a reliable security analyst** — it can
  hallucinate, miss threats, or produce false positives. All critical
  actions require Human-in-the-Loop (HITL) approval via Telegram.
- Do **not** deploy this as your only security control on any machine that
  matters. Use it to learn, experiment, and demonstrate concepts.

See [LICENSE](LICENSE) (AGPL-3.0) for the full no-warranty terms.

---

## Architecture

```
main.py
  └── services/
      ├── telegram/         (aiogram 3.x — DM + groups)
      ├── startup/          (monitor_loop → alert_queue → llm_analysis workers)
      ├── web_c2*.py        (aiohttp — LAN dashboard, Basic Auth + rate limit)
      ├── agent/            (ReAct FSM: INITIALIZE → PLANNER → EXECUTE → CRITIC → FINALIZE + ERROR)
      │   ├── bypass/       (17 fast-path handlers, chain of responsibility)
      │   ├── routing/      (hybrid semantic + keyword tool/skill routing)
      │   └── _nodes/       (FSM nodes + tool-level circuit breaker + tool ranker)
      ├── _skills_engine/   (15-skill engine — loads YAML skills from /skills)
      ├── llm_bridge/       (KoboldCpp / Qwen3.5-4B, circuit breaker, TPOT degradation)
      ├── bot_memory/       (SQLite + FTS5 + vectorlite HNSW, E5-large-instruct)
      ├── monitor_engine → monitor_analyzer → alert_dispatcher
      │                     (EMA baseline, 4-layer whitelist, Intel enrichment,
      │                      TTP detection → MITRE ATT&CK, score ≥85 → auto-queue kill)
      ├── fim_engine + yara_engine
      │                     (watchdog Observer → YARA auto-scan, 5 rules, 15 exts)
      ├── credential_monitor + leak_scanner
      ├── threat_hunter + pre_hunt_enricher
      │                     (APScheduler 6h → full ReAct → score → Telegram)
      ├── osint_hunter + osint_react_loop + osint_search
      │                     (engine-in-engine ReAct, 5-tier search waterfall)
      └── action_tools/     (HITL-protected OS remediation: firewall, defender, shell)
```

Full architecture reference (18 sections, including case studies on agentic
hallucination defense): [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

---

## Installation

### Requirements

| Requirement | Detail |
|-------------|--------|
| OS | Windows 10/11 (tests and lint gates run on Windows only) |
| Python | 3.12.2 (the only supported interpreter — a venv hook enforces this) |
| GPU | 6 GB VRAM minimum (for Qwen3.5-4B Q4_K_S via KoboldCpp) |
| LLM runtime | [KoboldCpp](https://github.com/LostRuins/koboldcpp) (local inference server) |
| Optional: Tesseract 5.x | For OCR skill (Hebrew + LTR) |
| Optional: opus-mt model | For offline translation skill |

### Steps

```powershell
# 1. Clone
git clone <repo-url> tactical_bot
cd tactical_bot

# 2. Create venv (Python 3.12.2 — the only supported interpreter)
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure from example files
copy config\channels.example.json config\channels.json
copy config\news_feeds.example.json config\news_feeds.json
copy config\trusted_devices.example.json config\trusted_devices.json
copy config\persona\USER.example.md config\persona\USER.md
# Edit each file — replace placeholders with your values.

# 5. Create .env with your API keys (see below)
#    The .env file is gitignored — never commit it.

# 6. Install gitleaks (for the secret/PII scan gate)
winget install gitleaks.gitleaks

# 7. Run lint gates
.\.venv\Scripts\python.exe bin\lint-gate.py

# 8. Run tests
.\.venv\Scripts\python.exe -m pytest tests/ -q

# 9. Start the bot
.\.venv\Scripts\python.exe main.py
```

### API Keys

The bot uses optional threat-intel API keys for enrichment. All are loaded
from environment variables (`.env`) — none are hardcoded.

| Key | Purpose | Where to get it |
|-----|---------|-----------------|
| `TELEGRAM_BOT_TOKEN` | Telegram bot delivery | [@BotFather](https://t.me/BotFather) |
| `TELEGRAM_CHAT_ID` | Your Telegram chat ID (admin) | [@userinfobot](https://t.me/userinfobot) |
| `VIRUSTOTAL_API_KEY` | VirusTotal enrichment | [virustotal.com → Join](https://www.virustotal.com/gui/join-us) |
| `ABUSEIPDB_API_KEY` | AbuseIPDB reputation | [abuseipdb.com → Register](https://www.abuseipdb.com/account) |
| `URLHAUS_AUTH_KEY` | URLhaus feed (abuse.ch) | [urlhaus.abuse.ch](https://urlhaus.abuse.ch/) |
| `THREATFOX_AUTH_KEY` | ThreatFox feed (abuse.ch) | [threatfox.abuse.ch](https://threatfox.abuse.ch/) |
| `NVD_API_KEY` | NVD CVE rate limit (optional) | [nvd.nist.gov → Request Key](https://nvd.nist.gov/developers/request-an-api-key) |

Links are to registration pages only — no keys are shared or embedded.

---

## Test & Quality Status

| Gate | Tool | Notes |
|------|------|-------|
| Cyclomatic Complexity | xenon | max-absolute=D, max-average=A, max-modules=C |
| Architectural Coupling | import-linter | Layer separation enforced |
| Dead Code | vulture | Whitelist auto-generated from tool registry |
| Lint + Format | ruff | |
| Type Check | mypy | Zero unsuppressed errors; 25 explicit, reviewed `type: ignore` suppressions |
| Security SAST | bandit | Medium+ blocks, Low = info |
| Secret + PII Scan | gitleaks | Custom rules: VT, AbuseIPDB, Telegram, ThreatFox, URLhaus, Maltiverse, NVD + local PII |
| File Length | file-length-gate | max 300 lines per file |
| Cognitive Complexity | cognitive-complexity-gate | Ratchet-protected, max 15 |
| Coverage | coverage-gate | Ratchet-protected |
| Dependency Audit | pip-audit | CVE-blocking |

**All gates and tests run on Windows only.** CI uses `windows-latest`.
Tests require a full Windows environment with all dependencies installed;
some tests are system-dependent (process introspection, Windows APIs,
KoboldCpp runtime) and will not collect or pass on Linux/macOS.

```powershell
# Full lint gate (all gates including coverage)
.\.venv\Scripts\python.exe bin\lint-gate.py

# Fast lint gate (skips coverage — for pre-commit)
.\.venv\Scripts\python.exe bin\lint-gate.py --fast

# Tests
.\.venv\Scripts\python.exe -m pytest tests/ -q
```

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3.12.2 (strict typing, Pydantic V2, async) |
| LLM | Qwen3.5-4B (Q4_K_S) via KoboldCpp (16K context, 6GB VRAM) |
| Embeddings | E5-large-instruct (1024-dim) |
| Vector Search | vectorlite HNSW (m=16, ef_construction=200) |
| Database | SQLite (WAL mode, 7 active databases — see [ARCHITECTURE.md](docs/ARCHITECTURE.md)) |
| Telegram | aiogram 3.x |
| Web Dashboard | aiohttp (Basic Auth, IP whitelist, rate-limited) |
| Scheduler | APScheduler |
| Skills | 15 skills (crypto, currency, email-forensics, file_analyst, firewall, geocode, intel, news-monitor, pcap-analyst, persistence-hunter, report-maker, stocks, translator, weather, web-scraper) |
| FIM + YARA | watchdog Observer + YARA (5 rules, 15 dangerous extensions) |
| TTP Detection | cmdline_analyzer (regex) → mitre_mapper |
| OCR | Tesseract 5.x (CPU-only, Hebrew + LTR) |
| Translation | opus-mt (offline) → MyMemory → deep-translator → LibreTranslate |
| License | AGPL-3.0-or-later |

---

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — Full architecture reference (18 sections)
- [`conceptual_repo/`](conceptual_repo/) — Engineering showcase variant (README + ARCHITECTURE only, no source code). Useful for sharing the design without the codebase.
- [`SECURITY.md`](SECURITY.md) — Vulnerability reporting policy
- [`AGENTS.md`](AGENTS.md) — Project rules (token economy, venv, verification)
- [`LICENSE`](LICENSE) — AGPL-3.0-or-later

---

## License

Copyright (C) 2026 Sentinel contributors.

This program is free software: you can redistribute it and/or modify it
under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE. See the [LICENSE](LICENSE) for the
full terms.
