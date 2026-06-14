"""Candidate findings emit a universal typed_fact claim per supporting fact.

This is the single activating move for the universal binder _t_typed_fact: a
deterministic candidate's supporting facts span families that currently have no
validator-typed claim (registry_persistence, network_ioc, service, scheduled_task,
wmi, privilege, handle). Emitting one typed_fact claim per fact -- declaring the
fact_type and copying the entity fields the binder keys on (pid/ip/port/hash/
event_id/value) -- makes every family bind through the EXISTING indexes.

Universal: no per-family code, no tool/case literals; keys only on fact_type +
the fact's own structural entity fields. Works for any present-or-future family.
"""
from sift_sentinel.analysis.candidate_findings import (
    build_candidate_semantic_findings,
    _typed_fact_claim,
)
from sift_sentinel.validation.typed_validator import TypedEvidenceDB, _t_typed_fact


def _cand(fact_ids):
    return {"candidate_id": "c1", "candidate_type": "x", "entity_key": "path:c:/x/y.exe",
            "validation_ready": True, "signals": ["anti_forensics_execution"],
            "score": 120, "source_tools": ["t"], "fact_ids": list(fact_ids)}


def _edb():
    return {"typed_facts": {
        "registry_persistence_fact": [{"fact_id": "r1", "fact_type": "registry_persistence_fact",
            "normalized_registry_path": "hklm/system/controlset001/control/safeboot/alternateshell"}],
        "network_ioc_fact": [{"fact_id": "n1", "fact_type": "network_ioc_fact", "remote_ip": "203.0.113.7"}],
        "privilege_fact": [{"fact_id": "p1", "fact_type": "privilege_fact", "pid": 4321}],
        "service_fact": [{"fact_id": "s1", "fact_type": "service_fact", "service_name": "foosvc"}],
    }}


def test_typed_fact_claim_helper_keys_on_structural_entities():
    # registry -> value(normalized path); network -> ip; privilege -> pid; service -> value
    assert _typed_fact_claim({"fact_type": "registry_persistence_fact",
        "normalized_registry_path": "hklm/x/y"}) == {"type": "typed_fact",
        "fact_type": "registry_persistence_fact", "value": "hklm/x/y"}
    assert _typed_fact_claim({"fact_type": "network_ioc_fact", "remote_ip": "203.0.113.9"})["ip"] == "203.0.113.9"
    assert _typed_fact_claim({"fact_type": "privilege_fact", "pid": 7})["pid"] == 7
    # no bindable entity -> None (never an empty claim)
    assert _typed_fact_claim({"fact_type": "mystery_fact"}) is None
    assert _typed_fact_claim({"pid": 1}) is None  # no fact_type


def test_candidate_emits_typed_fact_for_every_supporting_family():
    out = build_candidate_semantic_findings({"candidates": [_cand(["r1", "n1", "p1", "s1"])]},
                                            existing_findings=[], evidence_db=_edb())
    assert out, out
    fts = {c["fact_type"] for c in out[0]["claims"] if c.get("type") == "typed_fact"}
    for fam in ("registry_persistence_fact", "network_ioc_fact", "privilege_fact", "service_fact"):
        assert fam in fts, (fam, out[0]["claims"])


def test_emitted_typed_fact_claims_bind_via_indexes():
    # the emitted claim shape must bind through the universal checker + indexes
    out = build_candidate_semantic_findings({"candidates": [_cand(["r1", "n1"])]},
                                            existing_findings=[], evidence_db=_edb())
    tfs = [c for c in out[0]["claims"] if c.get("type") == "typed_fact"]
    tdb = TypedEvidenceDB({
        "typed_facts": _edb()["typed_facts"],
        "indexes": {
            "by_registry_path": {"hklm/system/controlset001/control/safeboot/alternateshell": ["r1"]},
            "by_ip": {"203.0.113.7": ["n1"]},
        },
    })
    bound = [c for c in tfs if (_t_typed_fact(c, tdb) or [None])[0] == "MATCH"]
    assert len(bound) == 2, [(c, _t_typed_fact(c, tdb)) for c in tfs]


def test_entity_less_fact_binds_via_fact_signature():
    # A family with no OS-primitive entity (WMI subscription keyed by consumer
    # class) still binds via the universal fact_signature existence anchor.
    f = {"fact_type": "wmi_subscription_fact", "fact_id": "w1",
         "canonical_entity_id": "wmi:active:ActiveScriptEventConsumer:abc",
         "fact_signature": "deadbeefcafe"}
    c = _typed_fact_claim(f)
    assert c["fact_signature"] == "deadbeefcafe"
    tdb = TypedEvidenceDB({"typed_facts": {"wmi_subscription_fact": [f]},
                           "indexes": {"by_fact_signature": {"deadbeefcafe": ["w1"]}}})
    assert (_t_typed_fact(c, tdb) or [None])[0] == "MATCH"


def test_ai_claim_without_signature_is_not_auto_bound():
    # an AI claim carries no fact_signature -> the sig anchor cannot mask a
    # hallucination; only entity binding applies.
    c = {"type": "typed_fact", "fact_type": "wmi_subscription_fact"}
    tdb = TypedEvidenceDB({"typed_facts": {"wmi_subscription_fact": [
        {"fact_id": "w1", "fact_type": "wmi_subscription_fact", "fact_signature": "x"}]},
        "indexes": {"by_fact_signature": {"x": ["w1"]}}})
    assert _t_typed_fact(c, tdb) is None
