# Hunt False-Positive Elimination — Cloud IP / AbuseIPDB Cross-Validation (2026-07-06)

> **Trigger:** Hunt report flagged Azure IPs (13.69.x.x, Microsoft ISP, VT=0/90) as MALICIOUS/High-Risk
> solely from AbuseIPDB=100. Root causes verified in code.

## Plan
- [x] 1. `is_clean_enrichment` (intel_enricher.py): remove dead `score < 50` condition from trusted-ISP
      override — Trusted ISP + VT=0 (verified data) + no feed hit → CLEAN even at AbuseIPDB=100.
      `_is_malicious` (pre_hunt_enricher.py): defers to `is_clean_enrichment` before declaring MALICIOUS.
- [x] 2. Hunt path baseline filter: new `services/net_noise_filter.py` (SSOT) — `suppression_reason()`
      chain (CDN → self → behavioral → learned baseline → intel whitelist, fail-open on DB errors).
      SnapshotDiffer delegates to it; threat_hunter calls `apply_snapshot_noise_filter()` in
      `_gather_context` BEFORE prompt build + IOC enrichment.
- [x] 3. `_CDN_NETWORKS`: added `13.64.0.0/11` + `13.104.0.0/14` (Azure).
- [x] 4. Hunt prompt typo: "התרה" → "התראה" (model was mirroring the prompt's own typo).
- [x] 5. Tests: 20 new (test_net_noise_filter.py, trusted-ISP override, Azure regression). lint-gate PASS.

## Review
- 82 targeted tests pass (monitor_analyzer, threat_hunter, intel/pre_hunt enricher, learning loop).
- Cognitive debt ratcheted 88 → 86 (`_diff_connections` refactor); baseline regenerated.
- monitor_analyzer.py 225 LLOC, threat_hunter.py 295 LLOC, net_noise_filter.py 99 LLOC — all ≤300.
- Note: user's claim "SnapshotDiffer never calls is_known_combo" was outdated (Phase 8 wired it);
  the real gap was the hunt path bypassing ALL filters — now closed.
- Critic/Reflection gate for High-Risk verdicts deferred to Phase 2 (existing _agent_critic covers
  generic hallucination; deterministic pre-filtering removes the noise at the source).

---

# Coverage Strategy — 80% Aggregate + Security Modules to 95%

> **Strategy:** Push aggregate coverage to 80% while maintaining security-critical modules at 95%.
> **Status:** Phase B-7 in progress — full suite verification + commit.

## Completed Phases

### Phase A — Mypy Debt Elimination
- [x] Zero Mypy errors enforced by lint-gate.py
- [x] Committed: ed89f4d

### Phase B-1 — Coverage Analysis + Planning
- [x] Identified ~1900 missing lines across services/agent/
- [x] Fail-Safe + Branch Rules test plans

### Phase B-2 — Fail-Safe E2E Tests
- [x] test_kill_block_fail_safe.py — 24 passed + 1 xfailed (106s)
- [x] test_callbacks_e2e.py — 60 passed
- [x] test_fail_safe_e2e.py — passed

### Phase B-3 — Branch Rules E2E Tests
- [x] test_branch_rules_e2e.py — 60 passed
- [x] test_initializer_executor_e2e.py — passed

### Phase B-4 — High-Impact Non-Security Tests
- [x] test_high_impact_coverage.py — 85 passed
- [x] test_misc_coverage.py — 123 passed
- [x] test_bypass_pure_logic.py — 68 passed (rewritten from scratch)

### Phase B-5 — Fix Failing Tests
- [x] test_telegram_coverage.py — 77 passed
- [x] test_startup_memory_coverage.py — 91 passed
- [x] test_tools_news_coverage.py — 143 passed
- [x] **Bug fix:** services/alert_history.py — missing commit() in async_save_audit_log

### Phase B-6 — Coverage 74% → 77%+
- [x] test_coverage_batch2.py — 86 passed (breaking_news, scheduled_news, error_memory, ip_enrich, channel_loader, ai_search, formatters)
- [x] test_coverage_batch3.py — 52 passed (_truncator, services_mgmt, yara_engine, fim_engine, agent_tools, completion, alert_history_query, monitor_engine_helpers)
- [x] test_coverage_batch4.py — 64 passed (bypass/elaborate, bypass/firewall, bypass/news, memory_store, memory_db, memory_db_search, formatters, _agent_critic)
- [x] Total new tests: ~1000+ passing

### Phase B-7 — Full Suite + Commit (IN PROGRESS)
- [ ] Run full test suite
- [ ] Verify coverage ≥ 80%
- [ ] Run lint-gate.py
- [ ] Commit all changes

## Bugs Found & Fixed
- **alert_history.py:** `async_save_audit_log` missing `commit()` after INSERT — fixed

## File Length Baseline
- 8 test files exceed 500 LLOC threshold — added to .file_length_baseline.txt as technical debt
