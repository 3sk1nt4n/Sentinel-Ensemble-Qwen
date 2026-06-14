"""Slot 31H-alpha TASK 4 -- entity_truth_summary.json/.md content.

dataset-agnostic by construction.
"""
from __future__ import annotations

import json
from pathlib import Path

from _etp_fixture import (
    SYN_CONFIRMED_FIDS,
    SYN_CONFIRMED_FILE,
    make_synthetic_run,
)

from sift_sentinel.entity_truth_package import (
    ENTITY_TRUTH_SUMMARY_JSON,
    ENTITY_TRUTH_SUMMARY_MD,
    build_entity_truth_package,
)

_REQUIRED_TOP_KEYS = {
    "schema_version",
    "source_run_id",
    "source_run_json_basename",
    "entity_counts",
    "confirmed_malicious_entities",
    "suspicious_entities",
    "benign_or_false_positive_entities",
    "inconclusive_entities",
    "synthesis_entities",
    "contradicted_entities",
    "gates",
}

_REQUIRED_COUNT_KEYS = {
    "finding_count",
    "entity_count",
    "entity_compression_ratio",
    "confirmed_atomic_finding_count",
    "confirmed_atomic_entity_count",
    "confirmed_atomic_compression_ratio",
    "contradicted_entity_count",
    "contradicted_confirmed_entity_count",
}


def _summary(tmp_path, **kw):
    run_json = make_synthetic_run(tmp_path, **kw)
    out = tmp_path / "pkg"
    build_entity_truth_package(run_json, out)
    return json.loads((out / ENTITY_TRUTH_SUMMARY_JSON).read_text()), out


def test_summary_has_required_top_keys(tmp_path):
    s, _ = _summary(tmp_path)
    assert _REQUIRED_TOP_KEYS <= set(s)
    assert _REQUIRED_COUNT_KEYS <= set(s["entity_counts"])


def test_empty_run_defaults_are_zero_or_null(tmp_path):
    # state_dir absent -> no findings -> documented defaults.
    run = {"state_dir": str(tmp_path / "nope"), "run_id": None}
    rj = tmp_path / "run_synth.json"
    rj.write_text(json.dumps(run))
    out = tmp_path / "pkg"
    build_entity_truth_package(rj, out)
    ec = json.loads(
        (out / ENTITY_TRUTH_SUMMARY_JSON).read_text())["entity_counts"]
    assert ec["finding_count"] == 0
    assert ec["entity_count"] == 0
    assert ec["entity_compression_ratio"] is None
    assert ec["confirmed_atomic_finding_count"] == 0
    assert ec["confirmed_atomic_entity_count"] == 0
    assert ec["confirmed_atomic_compression_ratio"] is None
    assert ec["contradicted_entity_count"] == 0
    assert ec["contradicted_confirmed_entity_count"] == 0


def test_confirmed_duplicates_collapse_under_one_entity(tmp_path):
    s, _ = _summary(tmp_path)
    conf = s["confirmed_malicious_entities"]
    # Three duplicate confirmed observations of one file -> 1 entity.
    assert len(conf) == 1
    e = conf[0]
    assert e["entity_key"] == "file:%s" % SYN_CONFIRMED_FILE
    assert sorted(e["source_finding_ids"]) == sorted(SYN_CONFIRMED_FIDS)
    ec = s["entity_counts"]
    assert ec["confirmed_atomic_finding_count"] == len(SYN_CONFIRMED_FIDS)
    assert ec["confirmed_atomic_entity_count"] == 1
    assert 0 < ec["confirmed_atomic_compression_ratio"] < 1


def test_contradicted_entity_routed_out_of_confirmed(tmp_path):
    s, _ = _summary(tmp_path, with_conflict=True)
    contradicted = s["contradicted_entities"]
    assert len(contradicted) >= 1
    for e in contradicted:
        assert e["tiebreaker_required"] is True
        assert e["has_react_conflict"] is True
    conf_keys = {
        e["entity_key"] for e in s["confirmed_malicious_entities"]}
    contr_keys = {e["entity_key"] for e in contradicted}
    assert conf_keys.isdisjoint(contr_keys)
    assert s["entity_counts"]["contradicted_confirmed_entity_count"] == 0


def test_summary_md_lists_confirmed_with_source_finding_ids(tmp_path):
    _, out = _summary(tmp_path)
    md = (out / ENTITY_TRUTH_SUMMARY_MD).read_text()
    assert "## Confirmed malicious entities" in md
    assert "source_finding_ids:" in md
    for fid in SYN_CONFIRMED_FIDS:
        assert fid in md
