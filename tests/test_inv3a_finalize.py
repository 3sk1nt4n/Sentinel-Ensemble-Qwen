"""Inv3a finalization pass (the "new SC") — Step 13AA.

Replaces the per-finding generative self-correction loop (Handler A, fact-level,
empirically 0 recoveries + ~45% of run input tokens) with ONE discriminative
triage pass (Handler B, interpretation-level) over the AMBIGUOUS buckets, run
just before Inv4 so the customer table is FP-swept and finalized.

Safety contract pinned here (preserves defense-layer 7 "code checks AI"):
  * adjudicates ONLY suspicious_needs_review + inconclusive_unresolved;
    confirmed_malicious_atomic and clear benign are never re-judged.
  * downgrade / reclassify / escalate-to-review only; promotion INTO
    confirmed_malicious_atomic requires the finding to already be deterministically
    eligible (eligibility_fn) -- the AI breaks ties among code-permitted buckets,
    it never manufactures a confirmation.
  * fail-closed: an unparseable / missing / out-of-range verdict keeps the
    original bucket.
  * pure: the AI call is injected (adjudicator_fn) so it is unit-testable.
Universal: keys on bucket names + disposition tokens + an eligibility predicate.
No case data.
"""
import json

from sift_sentinel.analysis.inv3a_finalize import (
    AMBIGUOUS_BUCKETS,
    build_inv3a_prompt,
    finalize_dispositions,
    parse_inv3a_verdicts,
    select_ambiguous,
)


def _buckets():
    return {
        "confirmed_malicious_atomic": [{"finding_id": "F1", "description": "lsass dump"}],
        "suspicious_needs_review": [
            {"finding_id": "F2", "description": "rwx region, no corroboration"},
            {"finding_id": "F3", "description": "service from temp path"},
        ],
        "benign_or_false_positive": [{"finding_id": "F4", "description": "signed update"}],
        "inconclusive_unresolved": [{"finding_id": "F5", "description": "partial netscan hit"}],
        "synthesis_narrative": [{"finding_id": "F6", "description": "overall story"}],
    }


# ── select_ambiguous ──────────────────────────────────────────────────────────
def test_select_ambiguous_picks_nonterminal_tiers():
    # WIDENED: inv3a now also sweeps the synthesis/context tier (F6) for recovery,
    # not just needs-review (F2,F3) + inconclusive (F5). The TERMINAL tiers stay
    # excluded: confirmed (F1, proven) + benign (F4, evidence-cleared FP).
    picked = {f["finding_id"] for f in select_ambiguous(_buckets())}
    assert picked == {"F2", "F3", "F5", "F6"}
    assert "F1" not in picked and "F4" not in picked   # confirmed + benign untouchable


def test_ambiguous_buckets_constant_is_the_nonterminal_tiers():
    assert set(AMBIGUOUS_BUCKETS) == {
        "suspicious_needs_review", "inconclusive_unresolved", "synthesis_narrative"}


# ── parse_inv3a_verdicts ──────────────────────────────────────────────────────
def test_parse_clean_json_array():
    txt = json.dumps([
        {"finding_id": "F2", "disposition": "false_positive", "reason": "JIT RWX"},
        {"finding_id": "F3", "disposition": "needs_review", "reason": "odd path"},
    ])
    out = parse_inv3a_verdicts(txt)
    assert out["F2"]["disposition"] == "false_positive"
    assert out["F3"]["disposition"] == "needs_review"


def test_parse_tolerates_prose_around_json():
    txt = "Here are my verdicts:\n```json\n" + json.dumps(
        [{"finding_id": "F5", "disposition": "inconclusive", "reason": "thin"}]
    ) + "\n```\nDone."
    out = parse_inv3a_verdicts(txt)
    assert out["F5"]["disposition"] == "inconclusive"


def test_parse_drops_unknown_disposition_tokens():
    txt = json.dumps([{"finding_id": "F2", "disposition": "definitely_evil", "reason": "x"}])
    out = parse_inv3a_verdicts(txt)
    assert "F2" not in out


def test_parse_object_wrapped_verdicts():
    # the live adjudicator returns {"verdicts": [...]} (the _live_call dict path).
    txt = json.dumps({"verdicts": [
        {"finding_id": "F2", "disposition": "false_positive", "reason": "noise"},
        {"finding_id": "F3", "disposition": "confirmed", "reason": "multi-source"},
    ]})
    out = parse_inv3a_verdicts(txt)
    assert out["F2"]["disposition"] == "false_positive"
    assert out["F3"]["disposition"] == "confirmed"


def test_parse_single_object_verdict():
    txt = json.dumps({"finding_id": "F5", "disposition": "inconclusive", "reason": "thin"})
    out = parse_inv3a_verdicts(txt)
    assert out["F5"]["disposition"] == "inconclusive"


# ── finalize_dispositions: the safety contract ────────────────────────────────
def _adjudicator(verdicts):
    """Return a fake adjudicator_fn(prompt)->str emitting the given verdicts."""
    return lambda prompt: json.dumps(verdicts)


def test_false_positive_verdict_moves_to_benign_and_badges():
    b = _buckets()
    adj = _adjudicator([{"finding_id": "F2", "disposition": "false_positive", "reason": "JIT RWX"}])
    new, ledger = finalize_dispositions(b, adj)
    ids_benign = {f["finding_id"] for f in new["benign_or_false_positive"]}
    ids_review = {f["finding_id"] for f in new["suspicious_needs_review"]}
    assert "F2" in ids_benign and "F2" not in ids_review
    moved = next(f for f in new["benign_or_false_positive"] if f["finding_id"] == "F2")
    assert moved.get("self_corrected") is True
    assert moved.get("_ai_finalize_to") == "benign_or_false_positive"
    assert isinstance(moved.get("self_correction"), dict)
    assert any(e["finding_id"] == "F2" and e["to"] == "benign_or_false_positive" for e in ledger)


def test_confirmed_verdict_on_ineligible_finding_is_clamped_to_review():
    b = _buckets()
    adj = _adjudicator([{"finding_id": "F5", "disposition": "confirmed", "reason": "looks bad"}])
    new, ledger = finalize_dispositions(b, adj, eligibility_fn=lambda f: False)
    assert "F5" not in {f["finding_id"] for f in new["confirmed_malicious_atomic"]}
    assert "F5" in {f["finding_id"] for f in new["suspicious_needs_review"]}


def test_confirmed_verdict_on_eligible_finding_is_promoted():
    b = _buckets()
    adj = _adjudicator([{"finding_id": "F2", "disposition": "confirmed", "reason": "multi-source"}])
    new, ledger = finalize_dispositions(b, adj, eligibility_fn=lambda f: f.get("finding_id") == "F2")
    assert "F2" in {f["finding_id"] for f in new["confirmed_malicious_atomic"]}


def test_default_eligibility_never_promotes():
    b = _buckets()
    adj = _adjudicator([{"finding_id": "F2", "disposition": "confirmed", "reason": "x"}])
    new, _ = finalize_dispositions(b, adj)
    assert "F2" not in {f["finding_id"] for f in new["confirmed_malicious_atomic"]}


def test_missing_or_garbage_verdict_keeps_original_bucket():
    b = _buckets()
    adj = lambda prompt: "not json at all"
    new, ledger = finalize_dispositions(b, adj)
    assert {f["finding_id"] for f in new["suspicious_needs_review"]} == {"F2", "F3"}
    assert {f["finding_id"] for f in new["inconclusive_unresolved"]} == {"F5"}
    assert ledger == []


def test_confirmed_and_benign_buckets_are_never_rejudged():
    b = _buckets()
    adj = _adjudicator([
        {"finding_id": "F1", "disposition": "false_positive", "reason": "x"},
        {"finding_id": "F4", "disposition": "confirmed", "reason": "x"},
    ])
    new, ledger = finalize_dispositions(b, adj, eligibility_fn=lambda f: True)
    assert {f["finding_id"] for f in new["confirmed_malicious_atomic"]} == {"F1"}
    assert {f["finding_id"] for f in new["benign_or_false_positive"]} == {"F4"}
    assert ledger == []


def test_no_op_reclassify_same_bucket_is_not_badged():
    b = _buckets()
    adj = _adjudicator([{"finding_id": "F2", "disposition": "needs_review", "reason": "still odd"}])
    new, ledger = finalize_dispositions(b, adj)
    f2 = next(f for f in new["suspicious_needs_review"] if f["finding_id"] == "F2")
    assert f2.get("self_corrected") is not True
    assert ledger == []


def test_pure_does_not_mutate_input_buckets():
    b = _buckets()
    adj = _adjudicator([{"finding_id": "F2", "disposition": "false_positive", "reason": "x"}])
    finalize_dispositions(b, adj)
    assert "F2" in {f["finding_id"] for f in b["suspicious_needs_review"]}


def test_inconclusive_to_false_positive_moves_and_badges():
    b = _buckets()
    adj = _adjudicator([{"finding_id": "F5", "disposition": "false_positive", "reason": "noise"}])
    new, ledger = finalize_dispositions(b, adj)
    assert "F5" in {f["finding_id"] for f in new["benign_or_false_positive"]}
    assert "F5" not in {f["finding_id"] for f in new["inconclusive_unresolved"]}
    assert any(e["finding_id"] == "F5" and e["from"] == "inconclusive_unresolved" for e in ledger)


# ── prompt universality ───────────────────────────────────────────────────────
def test_prompt_is_case_neutral_and_lists_findings():
    # Build from findings carrying NO case data; the prompt must contain only the
    # finding IDs + disposition vocabulary, never an IOC SHAPE of its own (IP /
    # hash / onion / hostname). Structural check -> no case names embedded here.
    import re as _re
    p = build_inv3a_prompt(select_ambiguous(_buckets()))
    assert "F2" in p and "F3" in p and "F5" in p
    assert not _re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", p)   # no IPv4
    assert not _re.search(r"\b[a-fA-F0-9]{32,}\b", p)          # no md5/sha hash
    assert ".onion" not in p.lower()
    for tok in ("false_positive", "needs_review", "confirmed", "inconclusive"):
        assert tok in p
