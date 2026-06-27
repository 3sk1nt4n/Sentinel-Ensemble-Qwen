"""Skipping zero-yield fact types from per-fact SCORING is byte-identical.

On a paired run, handle_fact + the two filesystem corpora are ~66% of all facts and
profiled to produce ZERO candidate signals, yet _score_fact/_blob over them dominate
Step-7. We skip them from scoring ONLY -- they still participate in _entity_keys
grouping (corroboration intact) and filesystem_timeline_fact still feeds the
mass-encryption pass -- so the candidate output is unchanged. Kill-switch
SIFT_CANDOBS_SKIP_NONSCORING=0.
"""
import json

from sift_sentinel.analysis import candidate_observations as co


def _evt(eid, msg):
    return {"fact_id": "e_%s" % eid, "source_tool": "parse_event_logs",
            "fact_type": "event_log_fact",
            "raw_excerpt": json.dumps({"EventID": eid, "Message": msg})}


def _handle(i):
    return {"fact_id": "h_%d" % i, "source_tool": "vol_handles",
            "fact_type": "handle_fact", "process_name": "x.exe",
            "value": "Event", "raw_excerpt": "noise %d" % i}


def _build(db):
    return co.build_candidate_observations(db)["candidates"]


def test_skip_nonscoring_produces_identical_candidates(monkeypatch):
    db = {"typed_facts": {
        "event_log_fact": [
            _evt("7045", "A service was installed. ImagePath: C:\\Windows\\Temp\\evil.exe"),
            _evt("1102", "The audit log was cleared"),
        ],
        "handle_fact": [_handle(i) for i in range(60)],
    }}
    monkeypatch.setattr(co, "_CANDOBS_SKIP_NONSCORING", False)
    full = _build(db)
    monkeypatch.setattr(co, "_CANDOBS_SKIP_NONSCORING", True)
    skipped = _build(db)
    assert json.dumps(full, sort_keys=True) == json.dumps(skipped, sort_keys=True)
    assert full, "the scoring event facts must still produce candidates"


def test_nonscoring_set_is_the_high_volume_zero_yield_types():
    assert co._NONSCORING_FACT_TYPES == frozenset(
        {"handle_fact", "filesystem_timeline_fact", "filesystem_listing_fact"})


def test_kill_switch_off_still_builds(monkeypatch):
    monkeypatch.setattr(co, "_CANDOBS_SKIP_NONSCORING", False)
    out = co.build_candidate_observations({"typed_facts": {"handle_fact": [_handle(0)]}})
    assert "candidates" in out
