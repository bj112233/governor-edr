"""Regression: missing EVIDENCE section must not fabricate missing_facts.

Bug (bot.log 2026-06-25 20:28): the CoVe critic returned VERDICT: PASS but
omitted the EVIDENCE section entirely. `_match_claims_to_evidence` hit the
`if not evidence: return list(claims)` branch, marking all 5 claims as
ungrounded. `_check_contradiction` then flipped PASS→FAIL ("missing_facts=5"),
triggering a false rejection that cascaded into circuit-breaker degradation
(score=0.00, no dispatch).

Fix: when grounded tool_data exists, an omitted EVIDENCE section is critic
laziness — return [] (no missing facts), mirroring the majority-NONE tiebreaker.
"""

from services.agent._agent_critic import _check_contradiction, _match_claims_to_evidence


def test_no_evidence_with_tool_data_is_not_missing():
    """Empty evidence + grounded tool_data → no missing facts (critic laziness)."""
    claims = ["CPU 22%", "RAM 49%", "IP 10.0.0.138 clean", "system stable", "no threats"]
    missing = _match_claims_to_evidence(claims, evidence=[], tool_data="CPU: 22% RAM: 49% snapshot ok")
    assert missing == []


def test_no_evidence_without_tool_data_is_hallucinated():
    """Empty evidence + no tool_data → all claims ungrounded (real hallucination)."""
    claims = ["CPU 22%", "RAM 49%"]
    missing = _match_claims_to_evidence(claims, evidence=[], tool_data="")
    assert missing == list(claims)


def test_mismatched_evidence_keys_not_missing():
    """Evidence present with rephrased keys + count mismatch → NOT missing.

    Bug (bot.log 2026-06-25 20:54): the 4B critic returned PASS with an EVIDENCE
    section whose entry count differed from CLAIMS and whose keys were rephrased
    (no text match). The text-based fallback used ev_map.get(key, 'NONE'), so every
    unmatched key counted as 'evidence=NONE' → all claims flagged missing → false
    PASS→FAIL flip → circuit-breaker degradation (score=0.00). An absent key is a
    parse mismatch, not an ungrounded claim.
    """
    claims = ["CPU low", "RAM ok", "IP clean", "no threats"]
    evidence = [
        ("the cpu", "1%"),
        ("memory", "48%"),
        ("ip addr", "clean"),
        ("threat", "none found"),
        ("extra", "x"),  # count mismatch forces the text-based fallback
    ]
    missing = _match_claims_to_evidence(claims, evidence, tool_data="x" * 3000)
    assert missing == []


def test_explicit_none_citation_still_flagged():
    """A claim whose key IS present and explicitly NONE must still be flagged."""
    claims = ["CPU low", "RAM ok", "phantom claim"]
    evidence = [
        ("cpu low", "1%"),
        ("ram ok", "48%"),
        ("phantom claim", "NONE"),
        ("extra", "x"),  # count mismatch → text-based fallback
    ]
    missing = _match_claims_to_evidence(claims, evidence, tool_data="x" * 3000)
    assert missing == ["phantom claim"]


def test_pass_verdict_survives_omitted_evidence():
    """End-to-end: PASS must NOT flip to FAIL when evidence omitted but data exists."""
    claims = ["CPU 22%", "RAM 49%"]
    missing = _match_claims_to_evidence(claims, evidence=[], tool_data="snapshot: CPU 22% RAM 49% disk OK")
    verdict = _check_contradiction(verdict=True, missing_facts=missing, has_flaw=False, reason="")
    assert verdict is True


def test_bare_fail_with_no_justification_flips_to_pass():
    """False-FAIL backstop: bare FAIL + missing=0 + flaw=False + reason='' → PASS.

    Bug (bot.log 2026-06-25 21:40/21:41): the 4B critic returned a 9-char
    "VERDICT: FAIL" with no CLAIMS, no EVIDENCE, no LOGICAL_FLAW, and empty
    REASON. _check_contradiction only guarded PASS→FAIL, so the bare FAIL
    passed through unchanged → 2 rejections → circuit-breaker degrade →
    score=0.00, no dispatch. A FAIL with zero supporting evidence is as
    spurious as a PASS with missing facts — flip it.
    """
    verdict = _check_contradiction(verdict=False, missing_facts=[], has_flaw=False, reason="")
    assert verdict is True


def test_fail_with_reason_stays_fail():
    """False-FAIL backstop must NOT fire when the critic gives a real reason."""
    verdict = _check_contradiction(verdict=False, missing_facts=[], has_flaw=False, reason="hallucinated data")
    assert verdict is False


def test_fail_with_missing_stays_fail():
    """False-FAIL backstop must NOT fire when missing_facts exist."""
    verdict = _check_contradiction(verdict=False, missing_facts=["claim X ungrounded"], has_flaw=False, reason="")
    assert verdict is False


def test_fail_with_flaw_stays_fail():
    """False-FAIL backstop must NOT fire when a logical flaw is present."""
    verdict = _check_contradiction(verdict=False, missing_facts=[], has_flaw=True, reason="")
    assert verdict is False


if __name__ == "__main__":
    test_no_evidence_with_tool_data_is_not_missing()
    test_no_evidence_without_tool_data_is_hallucinated()
    test_mismatched_evidence_keys_not_missing()
    test_explicit_none_citation_still_flagged()
    test_pass_verdict_survives_omitted_evidence()
    test_bare_fail_with_no_justification_flips_to_pass()
    test_fail_with_reason_stays_fail()
    test_fail_with_missing_stays_fail()
    test_fail_with_flaw_stays_fail()
    print("OK")
