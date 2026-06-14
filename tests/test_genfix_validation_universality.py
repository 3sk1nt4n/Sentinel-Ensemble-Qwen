"""UNIVERSALITY GUARD: every claim the gen-fix can emit is a claim type the
Step-10 validator RECOGNIZES -- so deterministic candidate findings never block
at validation for "unrecognized claim types", on ANY dataset.

This is the dataset-agnostic guarantee made concrete. The gen-fix builds claims
from the SAME typed facts the validator checks against, using only the recognized
claim types {path, hash, pid, connection, service}. Validation is self-consistent
BY CONSTRUCTION: a claim derived from a fact necessarily matches that fact.

The test runs the REAL validator over real gen-fix output -- not a mirrored
constant -- so a FUTURE signal that silently emits an un-validatable claim type
(e.g. a free-text 'artifact' or 'registry' claim with no checker) fails HERE,
before it can reach a live run and block at Step 10. The `_guard_has_teeth` test
proves the guard actually detects such a regression.

No host/IP/path/case literals: synthetic facts only.
"""
from __future__ import annotations

import pytest

from sift_sentinel.analysis.candidate_findings import (
    build_candidate_semantic_findings,
    _EMIT_ELIGIBLE,
)
from sift_sentinel.validation.validator import validate_finding


def _blocked_unrecognized(result) -> bool:
    """True iff the validator blocked the finding for an unrecognized claim type
    (validator.py step 1: status UNRESOLVED, detail 'unrecognized claim types:')."""
    detail = str(result.get("detail") or "").lower()
    return "unrecognized claim type" in detail


def _cand(entity_key, fact_ids, signals=("anti_forensics_execution",),
          cid="cand-uni", score=120):
    return {
        "candidate_id": cid,
        "candidate_type": "behavioral_anomaly",
        "entity_key": entity_key,
        "validation_ready": True,
        "signals": list(signals),
        "score": score,
        "source_tools": ["candidate_observations"],
        "fact_ids": list(fact_ids),
    }


def _edb_all_attrs():
    """A candidate attested across families so the gen-fix emits EVERY claim
    branch at once: path, hash, pid, connection, service."""
    return {"typed_facts": {
        "file_execution_fact": [
            {"fact_id": "fe-1", "normalized_path": "c:/x/tool.exe", "sha1": "a" * 40}],
        "process_fact": [
            {"fact_id": "pr-1", "pid": 1337, "process_name": "tool.exe"}],
        "network_fact": [
            {"fact_id": "nf-1", "remote_ip": "10.0.0.9"}],
        "service_fact": [
            {"fact_id": "sv-1", "service_name": "BadSvc"}],
    }}


def test_all_genfix_claim_branches_are_validator_recognized():
    edb = _edb_all_attrs()
    c = _cand("path:c:/x/tool.exe", ["fe-1", "pr-1", "nf-1", "sv-1"])
    out = build_candidate_semantic_findings({"candidates": [c]},
                                            existing_findings=[], evidence_db=edb)
    assert len(out) == 1, out
    f = out[0]
    types = {cl["type"] for cl in f["claims"]}
    # All five emit branches fired -> this is the full surface the validator sees.
    assert types == {"path", "hash", "pid", "connection", "service"}, types
    # The REAL Step-10 validator must NOT reject any of these as unrecognized.
    result = validate_finding(f, {}, evidence_db=edb)
    assert not _blocked_unrecognized(result), result.get("detail")


@pytest.mark.parametrize("signal", sorted(_EMIT_ELIGIBLE.keys()))
def test_each_emit_eligible_signal_validates_universally(signal):
    # Each emit-eligible signal, attested by a single path fact (the most common
    # real case). It must emit a finding whose every claim type the validator
    # recognizes -- on any dataset, regardless of which signal fired.
    edb = {"typed_facts": {"file_execution_fact": [
        {"fact_id": "f-1", "normalized_path": "c:/x/subject.exe"}]}}
    c = _cand("path:c:/x/subject.exe", ["f-1"], signals=[signal])
    out = build_candidate_semantic_findings({"candidates": [c]},
                                            existing_findings=[], evidence_db=edb)
    assert len(out) == 1, (signal, out)
    result = validate_finding(out[0], {}, evidence_db=edb)
    assert not _blocked_unrecognized(result), (signal, result.get("detail"))


@pytest.mark.parametrize("entity_key", [
    "pid:4242",
    "process:tool.exe:4242",
    "path:c:/x/tool.exe",
    "service:BadSvc",
    "ip:10.0.0.9",
    "peer:10.0.0.9:445",
])
def test_entity_key_fallback_claims_are_recognized(entity_key):
    # No evidence_db -> the gen-fix falls back to a claim derived from the
    # candidate entity_key. Every prefix it maps must be a recognized claim type.
    c = _cand(entity_key, ["does-not-resolve"])  # no evidence_db -> fallback path
    out = build_candidate_semantic_findings({"candidates": [c]}, existing_findings=[])
    assert len(out) == 1, (entity_key, out)
    result = validate_finding(out[0], {})
    assert not _blocked_unrecognized(result), (entity_key, result.get("detail"))


def test_guard_has_teeth_unknown_claim_type_is_caught():
    # Prove the guard detects a regression: a finding carrying a claim type the
    # validator has NO checker for IS flagged unrecognized. If a future signal
    # emitted such a claim, the tests above would fail exactly here.
    bogus = {"finding_id": "F999", "claims": [
        {"type": "totally_unknown_claim_type_xyz", "value": "whatever"}]}
    result = validate_finding(bogus, {})
    assert _blocked_unrecognized(result), result
