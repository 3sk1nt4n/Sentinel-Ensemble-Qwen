"""Slot 31F-alpha TASK 5 -- entity truth artifacts.

ENTITY_TRUTH_ARTIFACT_GATE + ENTITY_BUCKET_PARTITION_GATE. Synthetic
fixtures only; artifacts written to a tmp_path.
"""
from __future__ import annotations

import json

from sift_sentinel.entities import (
    ENTITY_BUCKET_PARTITION_GATE,
    ENTITY_BUCKETS,
    ENTITY_COMPRESSION_ARTIFACT_NAME,
    ENTITY_DISPOSITION_ARTIFACT_NAME,
    ENTITY_TRUTH_ARTIFACT_GATE,
    build_entity_truth,
    split_entity_artifacts,
    write_entity_artifacts,
)

_SCHEMA_KEYS = {
    "schema_version", "finding_count", "entity_count",
    "entity_compression_ratio", "confirmed_atomic_finding_count",
    "confirmed_atomic_entity_count", "confirmed_atomic_compression_ratio",
    "contradicted_entity_count", "contradicted_confirmed_entity_count",
    "confirmed_compression_ok", "buckets",
}


def _buckets():
    return {
        "confirmed_malicious_atomic": [
            {"finding_id": "FIXTURE_F1", "severity": "CRITICAL",
             "claims": [{"type": "hash", "sha1": "fixaaaa"}]},
            {"finding_id": "FIXTURE_F2", "severity": "CRITICAL",
             "claims": [{"type": "hash", "sha1": "fixaaaa"}]},
        ],
        "suspicious_needs_review": [
            {"finding_id": "FIXTURE_S1", "pid": 91801,
             "process": "FIXTURE_s.exe",
             "claims": [{"type": "pid", "pid": 91801}]}],
        "benign_or_false_positive": [
            {"finding_id": "FIXTURE_B1",
             "claims": [{"type": "hash", "sha1": "fixbbbb"}]}],
        "inconclusive_unresolved": [],
        "synthesis_narrative": [],
    }


def test_gate_identifiers_stable():
    assert ENTITY_TRUTH_ARTIFACT_GATE == "ENTITY_TRUTH_ARTIFACT_GATE"
    assert ENTITY_BUCKET_PARTITION_GATE == "ENTITY_BUCKET_PARTITION_GATE"


def test_schema_shape_complete():
    et = build_entity_truth(_buckets(), react_conflicts=None)
    assert set(et.keys()) == _SCHEMA_KEYS
    assert et["schema_version"] == "1.0"
    assert set(et["buckets"].keys()) == set(ENTITY_BUCKETS)
    # Counts derive from data, not initialization defaults.
    assert et["finding_count"] == 4
    assert et["confirmed_atomic_finding_count"] == 2
    assert et["confirmed_atomic_entity_count"] == 1


def test_bucket_partition_no_entity_in_two_buckets():
    et = build_entity_truth(_buckets(), react_conflicts=None)
    seen: dict[str, str] = {}
    for bname, items in et["buckets"].items():
        for e in items:
            k = e["entity_key"]
            assert k not in seen, (
                "entity %s in %s and %s" % (k, seen.get(k), bname))
            seen[k] = bname
    total = sum(len(v) for v in et["buckets"].values())
    assert total == et["entity_count"]


def test_artifacts_written_and_reloadable(tmp_path):
    et = build_entity_truth(_buckets(), react_conflicts=None)
    paths = write_entity_artifacts(tmp_path, et)
    dpath = tmp_path / ENTITY_DISPOSITION_ARTIFACT_NAME
    spath = tmp_path / ENTITY_COMPRESSION_ARTIFACT_NAME
    assert dpath.exists() and spath.exists()
    assert paths["disposition"] == dpath
    disposition = json.loads(dpath.read_text())
    summary = json.loads(spath.read_text())
    assert set(disposition["buckets"].keys()) == set(ENTITY_BUCKETS)
    assert summary["schema_version"] == "1.0"
    assert summary["confirmed_atomic_entity_count"] == 1
    assert "buckets" not in summary
    assert summary["bucket_counts"]["confirmed_malicious_atomic"] == 1


def test_split_round_trips_counts():
    et = build_entity_truth(_buckets(), react_conflicts=None)
    disposition, summary = split_entity_artifacts(et)
    for b in ENTITY_BUCKETS:
        assert summary["bucket_counts"][b] == len(disposition["buckets"][b])
