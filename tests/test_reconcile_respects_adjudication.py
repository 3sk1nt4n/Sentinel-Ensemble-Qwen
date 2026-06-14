"""Cross-bucket reconciliation must RESPECT an explicit benign adjudication.

Bug (a live paired run): inv3a adjudicated two registry-Run-key findings
benign with reasoning ('standard component, no unauthorized modification'), then
the escalate-only cross-bucket reconcile REVERSED them to needs-review to match a
weak, never-adjudicated sibling on the same key -- destroying a deliberate
decision and producing the same entity as both benign and suspicious.

Fix: a benign member carrying an explicit adjudication marker (ReAct FP verdict /
inv3a:false_positive / override:fp_routing_benign) is NOT escalated UNLESS a
CONFIRMED sibling exists (a proven confirmation still wins, and is surfaced).
Universal: keyed on the adjudication-source markers + bucket identity, no case
data. Kill-switch SIFT_RECONCILE_RESPECT_ADJUDICATION=0.
"""
from sift_sentinel.analysis.signature_reconcile import reconcile_cross_bucket_by_entity

REG = "hklm/software/microsoft/windows/currentversion/run/example"


def _reg(fid, key=REG, reasons=None):
    f = {"finding_id": fid, "claims": [{"type": "path", "value": key}]}
    if reasons:
        f["disposition_reasons"] = list(reasons)
    return f


def _empty():
    return {k: [] for k in ("confirmed_malicious_atomic", "suspicious_needs_review",
                            "benign_or_false_positive", "inconclusive_unresolved",
                            "synthesis_narrative")}


def test_adjudicated_benign_not_escalated_by_weak_sibling():
    b = _empty()
    b["suspicious_needs_review"] = [_reg("F011")]                      # weak, never adjudicated
    b["benign_or_false_positive"] = [_reg("F034", reasons=["inv3a:false_positive:standard component"])]
    new, ledger = reconcile_cross_bucket_by_entity(b)
    assert {f["finding_id"] for f in new["benign_or_false_positive"]} == {"F034"}
    assert "F034" not in {f["finding_id"] for f in new["suspicious_needs_review"]}
    assert ledger == []


def test_react_fp_benign_not_escalated():
    b = _empty()
    b["suspicious_needs_review"] = [_reg("F040")]
    b["benign_or_false_positive"] = [_reg("F006", reasons=["override:fp_routing_benign[entity_benign_propagation]"])]
    new, _ = reconcile_cross_bucket_by_entity(b)
    assert "F006" in {f["finding_id"] for f in new["benign_or_false_positive"]}


def test_confirmed_sibling_still_escalates_adjudicated_benign():
    # safety preserved: a PROVEN confirmation on the same entity still wins
    b = _empty()
    b["confirmed_malicious_atomic"] = [_reg("F100")]
    b["benign_or_false_positive"] = [_reg("F034", reasons=["inv3a:false_positive:looked benign"])]
    new, ledger = reconcile_cross_bucket_by_entity(b)
    assert "F034" in {f["finding_id"] for f in new["suspicious_needs_review"]}
    assert ledger and ledger[0]["from"] == "benign_or_false_positive"


def test_non_adjudicated_benign_still_escalates_legacy():
    # unchanged legacy behavior: a benign finding with NO adjudication marker escalates
    b = _empty()
    b["suspicious_needs_review"] = [_reg("F037")]
    b["benign_or_false_positive"] = [_reg("F013")]                     # no marker
    new, _ = reconcile_cross_bucket_by_entity(b)
    assert "F013" in {f["finding_id"] for f in new["suspicious_needs_review"]}


def test_kill_switch_restores_legacy_escalation(monkeypatch):
    monkeypatch.setenv("SIFT_RECONCILE_RESPECT_ADJUDICATION", "0")
    b = _empty()
    b["suspicious_needs_review"] = [_reg("F011")]
    b["benign_or_false_positive"] = [_reg("F034", reasons=["inv3a:false_positive:x"])]
    new, _ = reconcile_cross_bucket_by_entity(b)
    assert "F034" in {f["finding_id"] for f in new["suspicious_needs_review"]}
