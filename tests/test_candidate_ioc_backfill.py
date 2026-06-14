"""Empty IOCs/Artifacts cell fix (universal).

A deterministic candidate finding whose only validatable claim is an event_log
(event_id) carries NO entity VALUE -- so the IOCs/Artifacts column rendered '-'.
Live base-rd01: F048/F050 "lateral movement admin share: ip:203.0.113.5" showed
'-' there because the 5140 event_log claim has no ip field and primary_artifact
was unset.

Fix: the emitter backfills primary_artifact from the candidate entity_key, keyed
on the entity_key prefix SHAPE (ip/peer/path/service/process/pid), never on a
case-specific value. _ioc_bits already falls back to primary_artifact, so every
renderer surfaces the IOC. Pure additive field -> no claim/validation change.
"""
from __future__ import annotations

from sift_sentinel.analysis.candidate_findings import build_candidate_semantic_findings
from sift_sentinel.reporting.customer_findings_table_bucket_faithful import _ioc_bits


def _event_only_candidate(entity_key="ip:203.0.113.5"):
    # event_log_fact -> the only claim is {type:event_log, event_id}; no IOC value.
    return {
        "candidate_id": "cand-0004",
        "candidate_type": "lateral_movement_admin_share",
        "entity_key": entity_key,
        "validation_ready": True,
        "signals": ["admin_share_access"],
        "score": 120,
        "source_tools": ["extract_network_iocs", "parse_event_logs"],
        "fact_ids": ["el-1"],
    }


def _edb_with_event(eid="5140"):
    return {"typed_facts": {"event_log_fact": [
        {"fact_id": "el-1", "fact_type": "event_log_fact", "event_id": eid}]}}


def test_event_only_finding_gets_primary_artifact_from_entity_key():
    out = build_candidate_semantic_findings(
        {"candidates": [_event_only_candidate("ip:203.0.113.5")]},
        existing_findings=[], evidence_db=_edb_with_event())
    assert len(out) == 1, out
    f = out[0]
    # event-anchored: an event_log claim is present (now alongside a universal
    # typed_fact support claim) -- neither carries an IOC value, so the cell still
    # falls back to primary_artifact.
    assert any(c.get("type") == "event_log" for c in f["claims"]), f["claims"]
    assert f.get("primary_artifact") == "203.0.113.5"


def test_ioc_cell_not_empty_after_backfill():
    out = build_candidate_semantic_findings(
        {"candidates": [_event_only_candidate("ip:203.0.113.5")]},
        existing_findings=[], evidence_db=_edb_with_event())
    cell = _ioc_bits(out[0])
    assert "203.0.113.5" in cell and cell != "-", cell


def test_primary_artifact_universal_across_entity_shapes():
    # keyed on entity_key prefix shape, not a specific value.
    cases = {
        "ip:10.0.0.5": "10.0.0.5",
        "ip:10.0.0.5:445": "10.0.0.5",
        "service:psexesvc": "psexesvc",
        "path:c:/windows/temp/x.exe": "c:/windows/temp/x.exe",
    }
    for ek, expect in cases.items():
        out = build_candidate_semantic_findings(
            {"candidates": [_event_only_candidate(ek)]},
            existing_findings=[], evidence_db=_edb_with_event())
        assert out and out[0].get("primary_artifact") == expect, (ek, out)


def test_value_claim_findings_keep_their_ioc_unaffected():
    # A finding whose claim already carries an IOC value (path/hash) must be
    # unchanged: primary_artifact is a FALLBACK only, never overrides claim bits.
    edb = {"typed_facts": {"file_execution_fact": [
        {"fact_id": "fe-1", "path": "c:/users/x/sdelete.exe",
         "sha1": "7bcd946326b67f806b3db4595ede9fbdf29d0c36"}]}}
    c = {
        "candidate_id": "cand-9", "candidate_type": "defense_evasion_anti_forensics",
        "entity_key": "path:c:/users/x/sdelete.exe", "validation_ready": True,
        "signals": ["anti_forensics_execution"], "score": 120,
        "source_tools": ["get_amcache"], "fact_ids": ["fe-1"],
    }
    out = build_candidate_semantic_findings(
        {"candidates": [c]}, existing_findings=[], evidence_db=edb)
    cell = _ioc_bits(out[0])
    assert "sdelete.exe" in cell and cell != "-", cell
