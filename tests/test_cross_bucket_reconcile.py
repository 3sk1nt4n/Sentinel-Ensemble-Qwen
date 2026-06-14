"""Cross-bucket entity reconciliation (Fix A): one artefact must never appear as
BOTH benign and suspicious in the same report. The title-shape reconciler misses
this because the same artefact surfaces under different titles; this pass keys on
the exact artefact (registry key / file hash / fully-qualified path).

Universal / dataset-agnostic: keyed on artefact identity only, no case literal.
"""
from sift_sentinel.analysis.signature_reconcile import (
    reconcile_cross_bucket_by_entity,
)

# Truncated exactly as the live registry-persistence claim serialises it (the claim
# value is a registry path with no .exe suffix, so the exe-only dedup key misses it).
REG = "hklm/software/microsoft/windows nt/currentversion/image file"
SAFEBOOT = "hklm/system/controlset001/control/safeboot/alternateshell"


def _reg(fid, key=REG):
    return {"finding_id": fid, "claims": [{"type": "path", "value": key}]}


def _empty():
    return {
        "confirmed_malicious_atomic": [],
        "suspicious_needs_review": [],
        "benign_or_false_positive": [],
        "inconclusive_unresolved": [],
        "synthesis_narrative": [],
    }


def test_same_registry_key_in_benign_and_review_escalates_benign():
    b = _empty()
    b["suspicious_needs_review"] = [_reg("F037")]
    b["benign_or_false_positive"] = [_reg("F013")]
    new, ledger = reconcile_cross_bucket_by_entity(b)
    review = {f["finding_id"] for f in new["suspicious_needs_review"]}
    benign = {f["finding_id"] for f in new["benign_or_false_positive"]}
    assert "F013" in review          # benign escalated -> review
    assert "F013" not in benign
    assert "F037" in review          # original review preserved
    assert len(ledger) == 1
    assert ledger[0]["from"] == "benign_or_false_positive"
    assert ledger[0]["to"] == "suspicious_needs_review"


def test_uniform_benign_is_left_alone():
    # SafeBoot appears only in benign (twice) -> NOT contradicted -> untouched.
    b = _empty()
    b["benign_or_false_positive"] = [_reg("F014", SAFEBOOT), _reg("F027", SAFEBOOT)]
    new, ledger = reconcile_cross_bucket_by_entity(b)
    assert ledger == []
    assert {f["finding_id"] for f in new["benign_or_false_positive"]} == {"F014", "F027"}


def test_distinct_entities_not_grouped():
    b = _empty()
    b["suspicious_needs_review"] = [_reg("F037", REG)]
    b["benign_or_false_positive"] = [_reg("F099", "hklm/system/controlset001/services/legit/imagepath")]
    new, ledger = reconcile_cross_bucket_by_entity(b)
    assert ledger == []              # different keys -> no contradiction


def test_shared_hash_contradiction_escalates():
    h = "feedfacefeedfacefeedfacefeedfacefeedface"   # synthetic sha1, not case data
    b = _empty()
    b["suspicious_needs_review"] = [{"finding_id": "R", "claims": [{"sha1": h}]}]
    b["benign_or_false_positive"] = [{"finding_id": "B", "claims": [{"sha1": h}]}]
    new, ledger = reconcile_cross_bucket_by_entity(b)
    assert "B" in {f["finding_id"] for f in new["suspicious_needs_review"]}


def test_never_demotes_confirmed_never_auto_confirms():
    b = _empty()
    b["confirmed_malicious_atomic"] = [_reg("C", REG)]
    b["benign_or_false_positive"] = [_reg("B", REG)]
    new, ledger = reconcile_cross_bucket_by_entity(b)
    # confirmed stays confirmed; benign escalates to review (never to confirmed)
    assert {f["finding_id"] for f in new["confirmed_malicious_atomic"]} == {"C"}
    assert "B" in {f["finding_id"] for f in new["suspicious_needs_review"]}
    assert "B" not in {f["finding_id"] for f in new["confirmed_malicious_atomic"]}


def test_noncontradicted_run_is_noop():
    b = _empty()
    b["suspicious_needs_review"] = [_reg("F037", REG)]
    new, ledger = reconcile_cross_bucket_by_entity(b)
    assert ledger == []
    assert "F037" in {f["finding_id"] for f in new["suspicious_needs_review"]}


def test_partition_preserved_no_loss_no_dup():
    b = _empty()
    b["suspicious_needs_review"] = [_reg("F037")]
    b["benign_or_false_positive"] = [_reg("F013"), _reg("F028")]
    before = {f["finding_id"] for it in b.values() for f in it}
    new, _ = reconcile_cross_bucket_by_entity(b)
    after = {f["finding_id"] for it in new.values() for f in it}
    assert before == after           # every finding preserved exactly once
    # both benign twins escalated (both share the contradicted key)
    assert {"F013", "F028"} <= {f["finding_id"] for f in new["suspicious_needs_review"]}
