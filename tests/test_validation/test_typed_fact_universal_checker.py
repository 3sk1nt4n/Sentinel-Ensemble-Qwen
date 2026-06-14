"""Slot 31X-UNIVERSAL-ENTITY-KEYED-TYPED-CHECKER.

Covers the ``typed_fact`` claim checker (``_t_typed_fact``): one universal,
entity-keyed validator that confirms a typed fact of the claim's declared
``fact_type`` exists for an entity the claim itself names (pid / ip / port /
hash / event_id / path / registry path / task / service).

Contract under test:
  A. MATCH when a typed fact of the declared fact_type is present for a named
     entity, across each supported index family.
  B. The declared fact_type FILTERS every lookup -- a real entity carried by a
     different fact_type does NOT validate (no cross-index contamination).
  C. Conservative MATCH-or-None: an absent entity (or a missing fact_type)
     returns None, never a fabricated MISMATCH, so it can never block a finding.
  D. The checker is dispatched for ``type == "typed_fact"`` and is listed in
     TYPED_SUPPORTED_CLAIM_TYPES.
"""

from sift_sentinel.validation.typed_validator import (
    TYPED_SUPPORTED_CLAIM_TYPES,
    TypedEvidenceDB,
    _t_typed_fact,
    typed_check_claim,
)
from sift_sentinel.validation.validator import _build_validator_fact_refs


def _tdb():
    """Hand-built typed DB: one entity per index family, plus a PID that is
    carried by a DIFFERENT fact_type than the registry fact for the B leg."""
    ed = {
        "typed_facts": {
            "process_fact": [
                {"fact_id": "p1", "fact_type": "process_fact",
                 "pid": 1337, "process_name": "evil.exe"},
            ],
            "network_connection_fact": [
                {"fact_id": "n1", "fact_type": "network_connection_fact",
                 "foreign_addr": "203.0.113.50", "foreign_port": 4444},
            ],
            "amcache_fact": [
                {"fact_id": "h1", "fact_type": "amcache_fact",
                 "sha1": "a" * 40},
            ],
            "event_log_fact": [
                {"fact_id": "e1", "fact_type": "event_log_fact",
                 "event_id": 4624},
            ],
            "registry_persistence_fact": [
                {"fact_id": "r1", "fact_type": "registry_persistence_fact",
                 "registry_path": r"hklm\software\acme\run"},
            ],
            "scheduled_task_fact": [
                {"fact_id": "t1", "fact_type": "scheduled_task_fact",
                 "task_name": "eviltask"},
            ],
        },
        "indexes": {
            "by_pid": {"1337": ["p1"]},
            "by_ip": {"203.0.113.50": ["n1"]},
            "by_port": {"4444": ["n1"]},
            "by_hash": {"a" * 40: ["h1"]},
            "by_event_id": {"4624": ["e1"]},
            "by_registry_path": {r"hklm\software\acme\run": ["r1"]},
            "by_task_name": {"eviltask": ["t1"]},
        },
    }
    return TypedEvidenceDB(ed)


# ── A. positive MATCH across index families ──────────────────────────────

def test_pid_entity_matches():
    r = _t_typed_fact(
        {"type": "typed_fact", "fact_type": "process_fact", "pid": 1337},
        _tdb())
    assert r is not None and r[0] == "MATCH"


def test_ip_entity_matches_and_strips_port():
    # foreign_addr carries an ip:port -- the checker must normalize to the ip.
    r = _t_typed_fact(
        {"type": "typed_fact", "fact_type": "network_connection_fact",
         "foreign_addr": "203.0.113.50:4444"},
        _tdb())
    assert r is not None and r[0] == "MATCH"


def test_port_entity_matches():
    r = _t_typed_fact(
        {"type": "typed_fact", "fact_type": "network_connection_fact",
         "port": 4444},
        _tdb())
    assert r is not None and r[0] == "MATCH"


def test_hash_entity_matches_case_insensitive():
    r = _t_typed_fact(
        {"type": "typed_fact", "fact_type": "amcache_fact",
         "sha1": ("A" * 40)},
        _tdb())
    assert r is not None and r[0] == "MATCH"


def test_event_id_entity_matches():
    r = _t_typed_fact(
        {"type": "typed_fact", "fact_type": "event_log_fact",
         "event_id": 4624},
        _tdb())
    assert r is not None and r[0] == "MATCH"


def test_registry_path_value_matches_via_variant():
    r = _t_typed_fact(
        {"type": "typed_fact", "fact_type": "registry_persistence_fact",
         "value": r"HKLM\Software\Acme\Run"},
        _tdb())
    assert r is not None and r[0] == "MATCH"


def test_task_name_value_matches_lowercased():
    r = _t_typed_fact(
        {"type": "typed_fact", "fact_type": "scheduled_task_fact",
         "value": "EvilTask"},
        _tdb())
    assert r is not None and r[0] == "MATCH"


# ── B. fact_type FILTERS the lookup (no cross-index contamination) ────────

def test_fact_type_mismatch_does_not_validate():
    # PID 1337 exists, but only as a process_fact. A typed_fact claim that
    # declares network_connection_fact for that same PID must NOT match.
    r = _t_typed_fact(
        {"type": "typed_fact", "fact_type": "network_connection_fact",
         "pid": 1337},
        _tdb())
    assert r is None


# ── C. conservative MATCH-or-None ────────────────────────────────────────

def test_absent_entity_returns_none_not_mismatch():
    r = _t_typed_fact(
        {"type": "typed_fact", "fact_type": "process_fact", "pid": 9999},
        _tdb())
    assert r is None


def test_missing_fact_type_returns_none():
    r = _t_typed_fact(
        {"type": "typed_fact", "pid": 1337},  # no fact_type declared
        _tdb())
    assert r is None


def test_no_entity_keys_returns_none():
    r = _t_typed_fact(
        {"type": "typed_fact", "fact_type": "process_fact"},
        _tdb())
    assert r is None


# ── D. dispatch + registration ───────────────────────────────────────────

def test_typed_fact_is_a_supported_claim_type():
    assert "typed_fact" in TYPED_SUPPORTED_CLAIM_TYPES


def test_dispatch_routes_typed_fact_claim():
    r = typed_check_claim(
        {"type": "typed_fact", "fact_type": "process_fact", "pid": 1337},
        _tdb())
    assert r is not None and r[0] == "MATCH"


# ── E. validator_fact_refs provenance for typed_fact claims ──────────────
# A passing typed_fact claim must be recorded with its DECLARED fact_type in
# the durable fact references, not the generic "evidence_fact" default --
# otherwise value-to-artifact audit linkage is mislabeled.

def _match(claim, source="typed_evidence_db"):
    return {"result": "MATCH", "claim": claim, "source": source}


def test_fact_ref_uses_declared_fact_type_for_typed_fact():
    refs = _build_validator_fact_refs([
        _match({"type": "typed_fact", "fact_type": "scheduled_task_fact",
                "value": "EvilTask"}),
    ])
    assert len(refs) == 1
    assert refs[0]["fact_type"] == "scheduled_task_fact"
    assert refs[0]["claim_type"] == "typed_fact"


def test_fact_ref_falls_back_when_typed_fact_lacks_fact_type():
    refs = _build_validator_fact_refs([
        _match({"type": "typed_fact", "value": "EvilTask"}),  # no fact_type
    ])
    assert refs[0]["fact_type"] == "evidence_fact"


def test_fact_ref_non_typed_fact_claim_uses_map_unchanged():
    # Regression guard: the else-branch (legacy map) must stay intact.
    refs = _build_validator_fact_refs([
        _match({"type": "pid", "pid": 1337}),
    ])
    assert refs[0]["fact_type"] == "process_fact"


def test_fact_ref_only_built_for_match_checks():
    refs = _build_validator_fact_refs([
        {"result": "MISMATCH", "claim": {"type": "typed_fact",
                                         "fact_type": "process_fact"}},
    ])
    assert refs == []
