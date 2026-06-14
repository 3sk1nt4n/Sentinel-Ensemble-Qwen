"""Universal entity-index backfill: make every family queryable by the entities
its canonical_entity_id ALREADY encodes.

privilege/handle/session/sid facts encode their pid in canonical_entity_id
(e.g. 'privilege:pid:4:SeCreateTokenPrivilege', 'session:none:pid:4') but their
compilers declare no by_pid index, so they land only in by_fact_signature and
never bind. The index builder now backfills by_pid/by_ip from the canonical id,
and the typed_fact emitter copies the same pid/ip into the claim -- so they bind
via the EXISTING by_pid index, fact_type-filtered (invisible to process queries).

Universal: keys only on the system's own canonical encoding (pid:N / ip:X), no
per-family or case literals.
"""
from sift_sentinel.analysis.evidence_db import _ceid_entity_indexes
from sift_sentinel.analysis.candidate_findings import _typed_fact_claim
from sift_sentinel.validation.typed_validator import TypedEvidenceDB, _t_typed_fact


def test_ceid_backfill_extracts_pid_and_ip():
    assert _ceid_entity_indexes("privilege:pid:4:SeCreateTokenPrivilege") == {"by_pid": ["4"]}
    assert _ceid_entity_indexes("handle:pid:4:process:system pid 4") == {"by_pid": ["4"]}
    assert _ceid_entity_indexes("session:none:pid:4") == {"by_pid": ["4"]}
    assert _ceid_entity_indexes("connection:ip:203.0.113.9:pid:88") == {"by_pid": ["88"], "by_ip": ["203.0.113.9"]}
    assert _ceid_entity_indexes("reg:hklm/system/control/safeboot") == {}


def test_typed_fact_claim_extracts_pid_from_canonical():
    f = {"fact_type": "privilege_fact", "canonical_entity_id": "privilege:pid:4:SeDebugPrivilege"}
    c = _typed_fact_claim(f)
    assert c["pid"] == 4 and c["fact_type"] == "privilege_fact"


def test_backfilled_index_lets_privilege_handle_bind():
    # simulate a built DB: privilege + handle facts whose compilers gave no index,
    # backfilled into by_pid from canonical_entity_id.
    facts = {
        "privilege_fact": [{"fact_id": "pr1", "fact_type": "privilege_fact",
                            "canonical_entity_id": "privilege:pid:4:SeDebugPrivilege"}],
        "handle_fact": [{"fact_id": "h1", "fact_type": "handle_fact",
                         "canonical_entity_id": "handle:pid:4:process:lsass"}],
    }
    indexes = {"by_pid": {}}
    for fl in facts.values():
        for f in fl:
            for ix, keys in _ceid_entity_indexes(f["canonical_entity_id"]).items():
                for k in keys:
                    indexes.setdefault(ix, {}).setdefault(k, []).append(f["fact_id"])
    tdb = TypedEvidenceDB({"typed_facts": facts, "indexes": indexes})
    for fam in ("privilege_fact", "handle_fact"):
        c = _typed_fact_claim(facts[fam][0])
        assert (_t_typed_fact(c, tdb) or [None])[0] == "MATCH", (fam, c)
