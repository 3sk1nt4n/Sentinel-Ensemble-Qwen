"""Cross-bucket dedup must absorb a BENIGN duplicate of a surfaced artifact.

Live A+++ review: after canonical normalization, the same artifact still
appeared twice -- once needs-review, once benign (e.g. one LOLBIN execution
finding adjudicated benign while its same-artifact sibling stayed suspicious).
dedup_cross_bucket spanned only (confirmed, needs_review), so the benign
duplicate row survived and the report showed "same evidence, two verdicts".

Fix: BENIGN joins the span as the LOWEST priority. Most-severe wins: the
representative stays in the highest bucket present (confirmed > needs-review >
benign); the benign duplicate is absorbed -- its id recorded in
_merged_duplicate_ids and the ledger -- so its adjudication context travels
with the surfaced finding instead of contradicting it. Recall-favoring: a
merge can only ever RAISE visibility (benign row -> surfaced representative),
never demote or hide a detection. Benign-only duplicate groups are untouched
(within-bucket dedup's job). Kill-switch SIFT_XBUCKET_BENIGN_ABSORB=0 restores
the two-bucket span.

Universal: identity comes from entity_keys (exact hash/path), no case data.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.analysis.confirmed_dedup import dedup_cross_bucket  # noqa: E402

B = ("confirmed_malicious_atomic", "suspicious_needs_review",
     "benign_or_false_positive", "inconclusive_unresolved", "synthesis_narrative")


def _empty():
    return {k: [] for k in B}


def _f(fid, path, tools=1):
    return {"finding_id": fid,
            "source_tools": [f"tool_{i}" for i in range(tools)],
            "claims": [{"type": "path", "value": path}]}


def test_benign_duplicate_absorbed_into_review_representative():
    b = _empty()
    b["suspicious_needs_review"] = [_f("F1", "C:\\Windows\\System32\\example.exe", tools=3)]
    b["benign_or_false_positive"] = [_f("F2", "windows\\system32\\example.exe")]
    new, ledger = dedup_cross_bucket(b)
    assert len(new["suspicious_needs_review"]) == 1
    assert len(new["benign_or_false_positive"]) == 0
    rep = new["suspicious_needs_review"][0]
    assert rep["finding_id"] == "F1"
    assert "F2" in (rep.get("_merged_duplicate_ids") or [])
    assert any(e["finding_id"] == "F2" and e["into_bucket"] == "suspicious_needs_review"
               for e in ledger)


def test_benign_duplicate_absorbed_into_confirmed_representative():
    b = _empty()
    b["confirmed_malicious_atomic"] = [_f("F1", "C:\\Windows\\Temp\\tool.exe", tools=4)]
    b["benign_or_false_positive"] = [_f("F2", "C:\\\\Windows\\\\temp\\\\tool.exe")]
    new, _ = dedup_cross_bucket(b)
    assert len(new["confirmed_malicious_atomic"]) == 1
    assert len(new["benign_or_false_positive"]) == 0


def test_benign_only_duplicates_untouched():
    # two benign rows about the same artifact: within-bucket concern, not ours
    b = _empty()
    b["benign_or_false_positive"] = [
        _f("F1", "C:\\Windows\\System32\\example.exe"),
        _f("F2", "windows\\system32\\example.exe")]
    new, ledger = dedup_cross_bucket(b)
    assert len(new["benign_or_false_positive"]) == 2
    assert ledger == []


def test_different_artifacts_never_absorbed():
    b = _empty()
    b["suspicious_needs_review"] = [_f("F1", "C:\\Windows\\Temp\\alpha.exe")]
    b["benign_or_false_positive"] = [_f("F2", "C:\\Windows\\Temp\\bravo.exe")]
    new, ledger = dedup_cross_bucket(b)
    assert len(new["benign_or_false_positive"]) == 1
    assert ledger == []


def test_review_member_never_absorbed_into_benign():
    # most-severe wins: representative is ALWAYS the surfaced bucket, even when
    # the benign sibling is richer (more tools/claims).
    b = _empty()
    b["suspicious_needs_review"] = [_f("F1", "C:\\Windows\\System32\\example.exe", tools=1)]
    b["benign_or_false_positive"] = [_f("F2", "windows\\system32\\example.exe", tools=9)]
    new, _ = dedup_cross_bucket(b)
    assert len(new["suspicious_needs_review"]) == 1
    assert new["suspicious_needs_review"][0]["finding_id"] == "F1"
    assert len(new["benign_or_false_positive"]) == 0


def test_kill_switch_restores_two_bucket_span(monkeypatch):
    monkeypatch.setenv("SIFT_XBUCKET_BENIGN_ABSORB", "0")
    b = _empty()
    b["suspicious_needs_review"] = [_f("F1", "C:\\Windows\\System32\\example.exe")]
    b["benign_or_false_positive"] = [_f("F2", "windows\\system32\\example.exe")]
    new, ledger = dedup_cross_bucket(b)
    assert len(new["benign_or_false_positive"]) == 1     # legacy: benign untouched
    assert ledger == []


def test_confirmed_plus_review_unchanged_semantics():
    # the pre-existing two-bucket behavior is preserved
    b = _empty()
    b["confirmed_malicious_atomic"] = [_f("F1", "C:\\Windows\\Temp\\tool.exe", tools=4)]
    b["suspicious_needs_review"] = [_f("F2", "C:\\Windows\\temp\\tool.exe")]
    new, ledger = dedup_cross_bucket(b)
    assert len(new["confirmed_malicious_atomic"]) == 1
    assert len(new["suspicious_needs_review"]) == 0
    assert any(e["finding_id"] == "F2" for e in ledger)
