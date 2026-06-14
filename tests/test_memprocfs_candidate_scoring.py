"""FIX D (#3): MemProcFS FindEvil indicators surface as candidate observations.

The _c_memprocfs compiler already emits memprocfs_indicator_fact (committed) with
by_pid/by_path indexes, so the facts reach the DB and the universal typed checker
can bind them. The missing link was candidate scoring: memprocfs_indicator_fact
had NO branch in candidate_observations._score_fact, so FindEvil anomalies never
surfaced to Inv2 as candidates -> never became findings on a memory-only case.

This scores the FindEvil ANOMALY family (MemProcFS's own evil detector:
injection / unlinked module / bad parent / no-image PE, etc.) as promote-eligible,
while the benign baseline families (process/service/net/dns/module/handle
listings, timelines, prefetch, tasks) are suppressed so they cannot flood the
candidate set. Universal: keys on the record's semantic_family / semantic_role
(MemProcFS-internal structural categories), not on any malware/product name.

FP-safety: a FindEvil indicator is a single MEMORY source; it is promote-eligible
but the confirm gate + XCORR (e.g. same-PID malfind/ldrmodules) decide the final
tier -- a lone FindEvil hit does not auto-confirm.
"""
from sift_sentinel.analysis import candidate_observations as CO


def _findevil_fact():
    return {
        "fact_type": "memprocfs_indicator_fact",
        "entity_id": "memprocfs:findevil:pid-1337",
        "fact_id": "ff-1",
        "pid": 1337,
        "process_name": "evil.exe",
        "semantic_family": "findevil_indicators",
        "semantic_role": "anomaly_indicator",
        "indicator_type": "pe_inject",
        "path": "c:/users/v/appdata/local/temp/evil.exe",
        "source_tool": "run_memprocfs",
        "fields": {"semantic_family": "findevil_indicators",
                   "indicator_type": "pe_inject",
                   "description": "Injected PE with no backing image section"},
        "index": {"by_pid": ["1337"], "by_path": ["c:/users/v/appdata/local/temp/evil.exe"]},
    }


def _baseline_fact():
    return {
        "fact_type": "memprocfs_indicator_fact",
        "entity_id": "memprocfs:process:pid-4",
        "fact_id": "bl-1",
        "pid": 4,
        "process_name": "system",
        "semantic_family": "memory_process_baseline",
        "semantic_role": "process_listing",
        "indicator_type": "",
        "path": "",
        "source_tool": "run_memprocfs",
        "fields": {"semantic_family": "memory_process_baseline",
                   "semantic_role": "process_listing"},
        "index": {"by_pid": ["4"], "by_path": []},
    }


def test_findevil_indicator_scores_promote_eligible():
    score, signals, suppressions = CO._score_fact(_findevil_fact())
    assert score > 0, (score, signals, suppressions)
    assert any("findevil" in s or "memprocfs" in s for s in signals), signals


def test_baseline_listing_is_suppressed_not_scored():
    score, signals, suppressions = CO._score_fact(_baseline_fact())
    # benign MemProcFS baseline listing -> must NOT become a candidate
    assert score == 0, (score, signals)
    assert not signals


def test_findevil_becomes_candidate_observation():
    db = {"typed_facts": {"memprocfs_indicator_fact": [_findevil_fact(), _baseline_fact()]}}
    payload = CO.build_candidate_observations(db)
    cands = payload.get("candidates") or []
    # at least one candidate sourced from the FindEvil indicator
    hit = [c for c in cands if any("findevil" in str(s) or "memprocfs" in str(s)
                                   for s in (c.get("signals") or []))]
    assert hit, [c.get("signals") for c in cands]


def test_baseline_alone_does_not_promote():
    db = {"typed_facts": {"memprocfs_indicator_fact": [_baseline_fact()]}}
    payload = CO.build_candidate_observations(db)
    cands = payload.get("candidates") or []
    # a lone benign baseline listing must not surface as a scored candidate
    promoted = [c for c in cands if (c.get("score") or 0) > 0 and (c.get("signals"))]
    assert not promoted, promoted
