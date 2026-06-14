"""Slot 31F-alpha TASK 3 -- confirmed atomic entity dedup.

CONFIRMED_ATOMIC_ENTITY_DEDUP_GATE + ENTITY_COMPRESSION_RATIO_GATE.
Synthetic duplicate confirmed-atomic fixtures only.
"""
from __future__ import annotations

from sift_sentinel.entities import (
    CONFIRMED_ATOMIC_ENTITY_DEDUP_GATE,
    ENTITY_COMPRESSION_RATIO_GATE,
    build_entity_truth,
)


def _hashf(fid, sha1, filename="FIXTURE_tool.exe"):
    return {
        "finding_id": fid, "severity": "CRITICAL",
        "confidence_level": "MEDIUM", "source_tools": ["get_amcache"],
        "claims": [
            {"type": "hash", "sha1": sha1, "filename": filename},
        ],
    }


def test_gate_identifiers_stable():
    assert CONFIRMED_ATOMIC_ENTITY_DEDUP_GATE == \
        "CONFIRMED_ATOMIC_ENTITY_DEDUP_GATE"
    assert ENTITY_COMPRESSION_RATIO_GATE == "ENTITY_COMPRESSION_RATIO_GATE"


def test_three_findings_same_hash_compress_to_one_entity():
    shared = "fixturehashaaaabbbbccccddddeeee0000"
    buckets = {
        "confirmed_malicious_atomic": [
            _hashf("FIXTURE_F1", shared),
            _hashf("FIXTURE_F2", shared),
            _hashf("FIXTURE_F3", shared),
        ],
        "suspicious_needs_review": [],
        "benign_or_false_positive": [],
        "inconclusive_unresolved": [],
        "synthesis_narrative": [],
    }
    et = build_entity_truth(buckets, react_conflicts=None)
    assert et["confirmed_atomic_finding_count"] == 3
    assert et["confirmed_atomic_entity_count"] == 1
    assert et["confirmed_atomic_compression_ratio"] == round(1 / 3, 4)
    conf = et["buckets"]["confirmed_malicious_atomic"]
    assert len(conf) == 1
    assert sorted(conf[0]["source_finding_ids"]) == [
        "FIXTURE_F1", "FIXTURE_F2", "FIXTURE_F3"]


def test_distinct_hashes_do_not_over_compress():
    buckets = {
        "confirmed_malicious_atomic": [
            _hashf("FIXTURE_F1", "fixturehash1111",
                   filename="FIXTURE_one.exe"),
            _hashf("FIXTURE_F2", "fixturehash2222",
                   filename="FIXTURE_two.exe"),
        ],
        "suspicious_needs_review": [],
        "benign_or_false_positive": [],
        "inconclusive_unresolved": [],
        "synthesis_narrative": [],
    }
    et = build_entity_truth(buckets, react_conflicts=None)
    assert et["confirmed_atomic_finding_count"] == 2
    assert et["confirmed_atomic_entity_count"] == 2
    assert et["confirmed_atomic_compression_ratio"] == 1.0


def test_ratio_is_none_when_no_confirmed_findings():
    buckets = {
        "confirmed_malicious_atomic": [],
        "suspicious_needs_review": [
            {"finding_id": "FIXTURE_S1", "claims": []}],
        "benign_or_false_positive": [],
        "inconclusive_unresolved": [],
        "synthesis_narrative": [],
    }
    et = build_entity_truth(buckets, react_conflicts=None)
    assert et["confirmed_atomic_entity_count"] == 0
    assert et["confirmed_atomic_compression_ratio"] is None


def test_entity_count_never_exceeds_finding_count():
    buckets = {
        "confirmed_malicious_atomic": [
            _hashf("FIXTURE_F%d" % i, "fixturehash%d" % i)
            for i in range(5)
        ],
        "suspicious_needs_review": [],
        "benign_or_false_positive": [],
        "inconclusive_unresolved": [],
        "synthesis_narrative": [],
    }
    et = build_entity_truth(buckets, react_conflicts=None)
    assert et["entity_count"] <= et["finding_count"]
    assert 0.0 < et["entity_compression_ratio"] <= 1.0
