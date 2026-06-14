"""Confirmed-bucket dedup (lever 1). Same-artifact confirmed findings (shared hash
or shared full path) collapse to one representative; different artifacts never
merge. Universal: exact hash/path identity, no case literal, no name list."""
from sift_sentinel.analysis.confirmed_dedup import (
    entity_keys, dedup_confirmed, CONFIRMED,
)

_SHA = "e78b845045f7522c02e463a9b22db48e61ec0e54"
_SHA2 = "2013247c1481bb44bbebbb927a153b42e73b499f"


def _f(fid, tools, claims, title="finding"):
    return {"finding_id": fid, "title": title, "source_tools": tools, "claims": claims}


def test_entity_keys_use_hash_and_full_path_not_basename():
    f = _f("F1", ["t"], [{"type": "hash", "sha1": _SHA},
                         {"type": "path", "value": "C:/Windows/Temp/perfmon/PWDumpX.exe"}])
    ks = entity_keys(f)
    assert "h:" + _SHA in ks
    assert "p:c:/windows/temp/perfmon/pwdumpx.exe" in ks
    # a bare basename is NOT a path key (would collide across dirs)
    assert entity_keys(_f("F2", ["t"], [{"type": "path", "value": "PWDumpX.exe"}])) == set()


def test_same_hash_findings_collapse_keeping_most_corroborated():
    buckets = {
        CONFIRMED: [
            _f("F24", ["get_amcache"], [{"type": "hash", "sha1": _SHA}], "creds staged"),
            _f("F32", ["get_amcache", "extract_mft_timeline", "run_appcompatcacheparser"],
               [{"type": "hash", "sha1": _SHA}], "PWDumpX staged in temp"),
        ],
        "suspicious_needs_review": [], "inconclusive_unresolved": [],
        "benign_or_false_positive": [], "synthesis_narrative": [],
    }
    new, ledger = dedup_confirmed(buckets)
    ids = [f["finding_id"] for f in new[CONFIRMED]]
    assert ids == ["F32"]                              # the 3-tool finding is the representative
    assert new[CONFIRMED][0]["_merged_duplicate_ids"] == ["F24"]
    assert any(m["finding_id"] == "F24" and m["merged_into"] == "F32" for m in ledger)


def test_same_full_path_findings_collapse():
    p = {"type": "path", "value": "C:/Windows/Temp/perfmon/PWDumpX.exe"}
    buckets = {
        CONFIRMED: [_f("F28", ["get_amcache"], [p]), _f("F32", ["get_amcache", "extract_mft_timeline"], [p])],
        "suspicious_needs_review": [], "inconclusive_unresolved": [],
        "benign_or_false_positive": [], "synthesis_narrative": [],
    }
    new, ledger = dedup_confirmed(buckets)
    assert {f["finding_id"] for f in new[CONFIRMED]} == {"F32"}
    assert len(ledger) == 1


def test_different_artifacts_do_not_merge():
    buckets = {
        CONFIRMED: [
            _f("F24", ["t"], [{"type": "hash", "sha1": _SHA}], "PWDumpX"),
            _f("F06", ["t"], [{"type": "hash", "sha1": _SHA2}], "PsExec"),
        ],
        "suspicious_needs_review": [], "inconclusive_unresolved": [],
        "benign_or_false_positive": [], "synthesis_narrative": [],
    }
    new, ledger = dedup_confirmed(buckets)
    assert {f["finding_id"] for f in new[CONFIRMED]} == {"F24", "F06"}
    assert ledger == []


def test_different_dirs_same_basename_do_not_merge():
    buckets = {
        CONFIRMED: [
            _f("F1", ["t"], [{"type": "path", "value": "C:/Users/a/Temp/x1/setup.exe"}]),
            _f("F2", ["t"], [{"type": "path", "value": "C:/Users/b/Temp/x2/setup.exe"}]),
        ],
        "suspicious_needs_review": [], "inconclusive_unresolved": [],
        "benign_or_false_positive": [], "synthesis_narrative": [],
    }
    new, ledger = dedup_confirmed(buckets)
    assert {f["finding_id"] for f in new[CONFIRMED]} == {"F1", "F2"}  # different full paths
    assert ledger == []


def test_noop_on_single_or_empty_confirmed():
    assert dedup_confirmed({CONFIRMED: [], "suspicious_needs_review": []})[1] == []
    one = {CONFIRMED: [_f("F1", ["t"], [{"type": "hash", "sha1": _SHA}])],
           "suspicious_needs_review": []}
    assert dedup_confirmed(one)[1] == []


def test_ledger_accounts_for_every_removed_finding_and_keeps_partition():
    # PARTITION-GATE regression: every finding dedup removes from a bucket MUST be in
    # the ledger, so run_pipeline can drop the same ids from findings_final and keep
    # the buckets a clean partition of findings_final (the crash was a merged finding
    # vanishing from buckets but staying in findings_final).
    p = {"type": "path", "value": "C:/Windows/Temp/x/tool.exe"}
    findings = [_f("F1", ["t"], [p]),
                _f("F2", ["t", "u"], [p]),                         # same path as F1 -> dup
                _f("F3", ["t"], [{"type": "hash", "sha1": _SHA}])]  # distinct
    buckets = {
        CONFIRMED: list(findings),
        "suspicious_needs_review": [], "inconclusive_unresolved": [],
        "benign_or_false_positive": [], "synthesis_narrative": [],
    }
    before = {f["finding_id"] for f in findings}
    new, ledger = dedup_confirmed(buckets)
    after = {f["finding_id"] for f in new[CONFIRMED]}
    merged = {m["finding_id"] for m in ledger}
    assert merged and (before - after) == merged          # removed == ledgered
    assert before == (after | merged)                     # nothing vanishes unaccounted

    # simulate the run_pipeline findings_final sync -> buckets must partition it
    findings_final = [f for f in findings if f["finding_id"] not in merged]
    bucket_total = sum(len(v) for v in new.values() if isinstance(v, list))
    assert bucket_total == len(findings_final)


def test_dedup_review_collapses_same_artifact_in_review_bucket():
    from sift_sentinel.analysis.confirmed_dedup import dedup_review, NEEDS_REVIEW
    p = {"type": "path", "value": "C:/Users/u/AppData/Local/Temp/a.exe"}
    buckets = {
        CONFIRMED: [],
        NEEDS_REVIEW: [_f("F15", ["get_amcache"], [p]),
                       _f("F5", ["get_amcache", "vol_psscan"], [p])],
        "inconclusive_unresolved": [], "benign_or_false_positive": [],
        "synthesis_narrative": [],
    }
    new, ledger = dedup_review(buckets)
    assert {f["finding_id"] for f in new[NEEDS_REVIEW]} == {"F5"}   # 2-tool rep kept
    assert len(ledger) == 1
    # confirmed dedup must NOT touch the review bucket
    new2, ledger2 = dedup_confirmed(buckets)
    assert {f["finding_id"] for f in new2[NEEDS_REVIEW]} == {"F15", "F5"}
    assert ledger2 == []
