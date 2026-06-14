"""Slot 31F-alpha TASK 4 -- contradiction-aware routing.

ENTITY_CONTRADICTION_BLOCKS_CONFIRMED_GATE +
ENTITY_TIEBREAKER_REQUIRED_GATE. Synthetic fixtures only; ReAct
conflicts built through the real 5d-alpha pipeline.
"""
from __future__ import annotations

from sift_sentinel.entities import (
    ENTITY_CONTRADICTION_BLOCKS_CONFIRMED_GATE,
    ENTITY_TIEBREAKER_REQUIRED_GATE,
    build_entity_truth,
)
from sift_sentinel.react_verdicts import (
    build_react_entity_verdict_ledger,
    detect_react_entity_contradictions,
)


def _rec(**kw):
    base = {
        "verdict": "malicious", "scope": None, "pid": None,
        "process_name": None, "file": None, "network": None,
        "chain_members": None, "source_finding_ids": [],
        "evidence_refs": [], "excerpt": "",
    }
    base.update(kw)
    return base


def _conflicts_for_pid(pid, fid_mal, fid_ben):
    ledger = build_react_entity_verdict_ledger([
        _rec(pid=pid, process_name="FIXTURE_svc.exe", verdict="malicious",
             source_finding_ids=[fid_mal],
             excerpt="CONCLUDED -- malicious injection"),
        _rec(pid=pid, process_name="FIXTURE_svc.exe", verdict="benign",
             source_finding_ids=[fid_ben],
             excerpt="CONCLUDED -- signed, false positive"),
    ])
    return detect_react_entity_contradictions(ledger)


def test_gate_identifiers_stable():
    assert ENTITY_CONTRADICTION_BLOCKS_CONFIRMED_GATE == \
        "ENTITY_CONTRADICTION_BLOCKS_CONFIRMED_GATE"
    assert ENTITY_TIEBREAKER_REQUIRED_GATE == \
        "ENTITY_TIEBREAKER_REQUIRED_GATE"


def test_contradicted_entity_never_enters_confirmed_bucket():
    pid = 91500
    conflicts = _conflicts_for_pid(pid, "FIXTURE_FM", "FIXTURE_FB")
    assert conflicts  # 5d-alpha detected the contradiction
    buckets = {
        "confirmed_malicious_atomic": [{
            "finding_id": "FIXTURE_FM", "pid": pid,
            "process": "FIXTURE_svc.exe", "severity": "CRITICAL",
            "claims": [{"type": "pid", "pid": pid,
                        "process": "FIXTURE_svc.exe"},
                       {"type": "hash", "sha1": "fixaa"}],
        }],
        "suspicious_needs_review": [{
            "finding_id": "FIXTURE_FB", "pid": pid,
            "process": "FIXTURE_svc.exe", "claims": [
                {"type": "pid", "pid": pid}],
        }],
        "benign_or_false_positive": [],
        "inconclusive_unresolved": [],
        "synthesis_narrative": [],
    }
    et = build_entity_truth(buckets, react_conflicts=conflicts)
    conf_fids = {
        fid
        for e in et["buckets"]["confirmed_malicious_atomic"]
        for fid in e["source_finding_ids"]
    }
    assert "FIXTURE_FM" not in conf_fids
    assert "FIXTURE_FB" not in conf_fids
    assert et["contradicted_entity_count"] >= 1
    contradicted = [
        e for v in et["buckets"].values() for e in v
        if e.get("has_react_conflict")
    ]
    assert contradicted
    for e in contradicted:
        assert e["tiebreaker_required"] is True
        assert e["entity_disposition"] == "suspicious_needs_review"


def test_clean_confirmed_entity_still_confirms():
    conflicts = _conflicts_for_pid(91600, "FIXTURE_OTHER_M",
                                   "FIXTURE_OTHER_B")
    buckets = {
        "confirmed_malicious_atomic": [{
            "finding_id": "FIXTURE_CLEAN", "severity": "CRITICAL",
            "claims": [{"type": "hash", "sha256": "fixclean1234"},
                       {"type": "hash", "sha256": "fixclean5678"}],
        }],
        "suspicious_needs_review": [],
        "benign_or_false_positive": [],
        "inconclusive_unresolved": [],
        "synthesis_narrative": [],
    }
    et = build_entity_truth(buckets, react_conflicts=conflicts)
    conf_fids = {
        fid
        for e in et["buckets"]["confirmed_malicious_atomic"]
        for fid in e["source_finding_ids"]
    }
    assert "FIXTURE_CLEAN" in conf_fids


def test_chain_member_not_promoted_to_confirmed_by_chain_alone():
    # A chain-scope confirmed finding routes to synthesis at entity
    # level; its member processes are NOT confirmed entities.
    buckets = {
        "confirmed_malicious_atomic": [{
            "finding_id": "FIXTURE_CHAIN", "is_synthesis": True,
            "severity": "HIGH",
            "claims": [
                {"type": "pid", "pid": 91700, "process": "FIXTURE_a.exe"},
                {"type": "pid", "pid": 91701, "process": "FIXTURE_b.exe"},
                {"type": "pid", "pid": 91702, "process": "FIXTURE_c.exe"},
            ],
        }],
        "suspicious_needs_review": [],
        "benign_or_false_positive": [],
        "inconclusive_unresolved": [],
        "synthesis_narrative": [],
    }
    et = build_entity_truth(buckets, react_conflicts=None)
    assert et["buckets"]["confirmed_malicious_atomic"] == []
    syn = et["buckets"]["synthesis_narrative"]
    assert any(e["entity_scope"] == "chain" for e in syn)
    for e in syn:
        assert not e["entity_key"].startswith("process:")
