"""Slot 31F-alpha TASK 2 -- entity grouping. ENTITY_GROUPING_GATE.

Synthetic fixtures only.
"""
from __future__ import annotations

from sift_sentinel.entities import (
    ENTITY_GROUPING_GATE,
    group_findings_by_entity,
)


def _f(fid, **kw):
    base = {"finding_id": fid, "claims": [], "source_tools": []}
    base.update(kw)
    return base


def test_gate_identifier_stable():
    assert ENTITY_GROUPING_GATE == "ENTITY_GROUPING_GATE"


def test_group_required_fields_present():
    findings = [_f("FIXTURE_F1", pid=91100, process="FIXTURE_a.exe",
                    severity="HIGH", confidence_level="MEDIUM",
                    source_tools=["vol_pstree"], title="t1",
                    final_disposition="confirmed_malicious_atomic",
                    claims=[{"type": "pid", "pid": 91100}])]
    groups = group_findings_by_entity(findings=findings)
    key = "process:91100:fixture_a.exe"
    assert key in groups
    g = groups[key]
    for fld in ("entity_key", "entity_scope", "source_finding_ids",
                "source_buckets", "source_titles", "source_tools",
                "claim_count_total", "highest_severity",
                "highest_confidence", "has_react_conflict",
                "conflict_types", "tiebreaker_required",
                "recommended_entity_disposition"):
        assert fld in g, fld
    assert g["source_finding_ids"] == ["FIXTURE_F1"]
    assert g["highest_severity"] == "high"
    assert g["claim_count_total"] == 1


def test_two_findings_same_entity_collapse_to_one_group():
    findings = [
        _f("FIXTURE_F1", pid=91200, process="FIXTURE_x.exe",
           final_disposition="suspicious_needs_review"),
        _f("FIXTURE_F2", pid=91200, process="FIXTURE_x.exe",
           final_disposition="suspicious_needs_review"),
    ]
    groups = group_findings_by_entity(findings=findings)
    g = groups["process:91200:fixture_x.exe"]
    assert sorted(g["source_finding_ids"]) == ["FIXTURE_F1", "FIXTURE_F2"]


def test_buckets_input_records_source_bucket():
    buckets = {
        "confirmed_malicious_atomic": [
            _f("FIXTURE_F9", claims=[{"type": "hash", "sha1": "AA"}])],
        "benign_or_false_positive": [],
    }
    groups = group_findings_by_entity(buckets=buckets)
    g = groups["hash:sha1:aa"]
    assert g["source_buckets"] == ["confirmed_malicious_atomic"]
    assert g["recommended_entity_disposition"] == \
        "confirmed_malicious_atomic"


def test_react_conflict_propagates_and_blocks_confirmed_recommendation():
    findings = [
        _f("FIXTURE_F1", pid=91300, process="FIXTURE_c.exe",
           final_disposition="confirmed_malicious_atomic",
           react_entity_conflict=True,
           react_entity_conflict_reason="direct_entity_verdict_conflict",
           claims=[{"type": "pid", "pid": 91300}]),
    ]
    groups = group_findings_by_entity(findings=findings)
    g = groups["process:91300:fixture_c.exe"]
    assert g["has_react_conflict"] is True
    assert g["tiebreaker_required"] is True
    assert "direct_entity_verdict_conflict" in g["conflict_types"]
    assert g["recommended_entity_disposition"] != \
        "confirmed_malicious_atomic"
