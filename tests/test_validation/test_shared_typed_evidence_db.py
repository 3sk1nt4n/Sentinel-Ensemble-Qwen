"""Step-10 perf: TypedEvidenceDB is built once per evidence_db and reused across
findings (was rebuilt per finding over ~370k facts -> wall=106s, avg=2.65s/finding,
GIL-serialized so the 8-thread pool gave no speedup).

These lock the caching invariant; the full-suite revert-diff A/B proves validation
behavior is byte-unchanged. Universal: identity-keyed, no case data."""

import sift_sentinel.validation.validator as v
from sift_sentinel.validation.validator import _shared_typed_evidence_db


def _ed(fact_id="f1", ftype="process_fact"):
    """Minimal evidence_db sidecar with one typed fact."""
    return {
        "typed_facts": {ftype: [{"fact_id": fact_id, "fact_type": ftype, "pid": 4}]},
        "indexes": {"by_pid": {"4": [fact_id]}},
    }


def test_same_evidence_db_object_reuses_instance():
    ed = _ed()
    a = _shared_typed_evidence_db(ed)
    b = _shared_typed_evidence_db(ed)
    assert a is not None
    assert a is b  # same dict object -> same cached TypedEvidenceDB


def test_different_evidence_db_objects_get_distinct_instances():
    a = _shared_typed_evidence_db(_ed("f1"))
    b = _shared_typed_evidence_db(_ed("f2"))
    assert a is not b


def test_falsy_evidence_db_returns_none():
    assert _shared_typed_evidence_db(None) is None
    assert _shared_typed_evidence_db({}) is None


def test_construction_is_hoisted_across_repeated_calls(monkeypatch):
    """N calls with the SAME evidence_db build TypedEvidenceDB exactly once."""
    calls = {"n": 0}
    real = v.TypedEvidenceDB

    def _counting(ed):
        calls["n"] += 1
        return real(ed)

    monkeypatch.setattr(v, "TypedEvidenceDB", _counting)
    ed = _ed("hoist-probe")  # fresh object -> guaranteed initial cache miss
    for _ in range(10):
        _shared_typed_evidence_db(ed)
    assert calls["n"] == 1


def test_shared_instance_resolves_facts():
    ed = _ed("f1")
    tdb = _shared_typed_evidence_db(ed)
    assert tdb.available() is True
    facts = tdb.facts_by_index("by_pid", 4, "process_fact")
    assert facts and facts[0]["fact_id"] == "f1"
