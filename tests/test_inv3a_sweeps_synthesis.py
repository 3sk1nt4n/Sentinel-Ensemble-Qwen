"""inv3a must also sweep the SYNTHESIS (context) tier, not just needs-review +
inconclusive.

Live acme run: real behavioural findings (egress F040, staging F034/F044,
sdelete-download F037) were parked in synthesis_narrative and inv3a never
re-examined them, so they could never be recovered to needs-review/confirmed.
The user wants the AI final pass to sweep the LOW/INFO/context recovery tier.

SAFETY PRESERVED: the TERMINAL tiers stay untouched -- confirmed (already
proven) and benign_or_false_positive (evidence-cleared FPs; re-judging them
would undo the ReAct FP discipline). Promotion into confirmed is still gated by
the eligibility predicate (fail-closed).
"""
import json

from sift_sentinel.analysis.inv3a_finalize import (
    finalize_dispositions,
    select_ambiguous,
)


def _buckets():
    return {
        "confirmed_malicious_atomic": [{"finding_id": "C1", "description": "proven"}],
        "suspicious_needs_review": [{"finding_id": "S1", "description": "a"}],
        "inconclusive_unresolved": [{"finding_id": "I1", "description": "thin"}],
        "benign_or_false_positive": [{"finding_id": "B1", "description": "jit rwx, cleared"}],
        "synthesis_narrative": [{"finding_id": "N1", "description": "egress outlier context"}],
    }


def _const(text):
    return lambda _prompt: text


def test_synthesis_is_swept():
    assert "N1" in {f["finding_id"] for f in select_ambiguous(_buckets())}


def test_synthesis_finding_can_be_recovered_to_needs_review():
    adj = _const(json.dumps({"verdicts": [
        {"finding_id": "N1", "disposition": "needs_review", "reason": "real egress"}]}))
    new, ledger = finalize_dispositions(_buckets(), adj)
    assert "N1" in {f["finding_id"] for f in new["suspicious_needs_review"]}
    assert "N1" not in {f["finding_id"] for f in new["synthesis_narrative"]}
    assert any(e["finding_id"] == "N1" and e["to"] == "suspicious_needs_review"
               for e in ledger)


def test_terminal_tiers_still_untouchable():
    # confirmed + benign must remain inv3a-proof (FP discipline preserved).
    adj = _const(json.dumps({"verdicts": [
        {"finding_id": "C1", "disposition": "false_positive", "reason": "x"},
        {"finding_id": "B1", "disposition": "confirmed", "reason": "x"}]}))
    new, ledger = finalize_dispositions(_buckets(), adj, eligibility_fn=lambda f: True)
    assert {f["finding_id"] for f in new["confirmed_malicious_atomic"]} == {"C1"}
    assert {f["finding_id"] for f in new["benign_or_false_positive"]} == {"B1"}
    assert ledger == []


def test_synthesis_promotion_to_confirmed_still_eligibility_gated():
    adj = _const(json.dumps({"verdicts": [
        {"finding_id": "N1", "disposition": "confirmed", "reason": "trust me"}]}))
    # no eligibility_fn -> cannot promote; clamps to needs_review, never confirmed.
    new, _ = finalize_dispositions(_buckets(), adj)
    assert "N1" not in {f["finding_id"] for f in new["confirmed_malicious_atomic"]}
    assert "N1" in {f["finding_id"] for f in new["suspicious_needs_review"]}
