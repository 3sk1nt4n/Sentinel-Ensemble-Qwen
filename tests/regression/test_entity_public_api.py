"""Slot 31F-alpha-fix -- public integration callables.

entity_disposition_buckets() and entity_compression_summary() must be
real top-level callables with the contracted shapes. Synthetic
fixtures for unit behavior; the recorded diagnostic run for the
existing-run gate proof (skips cleanly if absent).
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from sift_sentinel import entities as E


def test_both_functions_are_public_callables():
    assert callable(E.entity_disposition_buckets)
    assert callable(E.entity_compression_summary)
    assert "entity_disposition_buckets" in E.__all__
    assert "entity_compression_summary" in E.__all__


def _confirmed_dup_buckets():
    shared = "fixturehashaaaabbbbccccdddd"
    mk = lambda fid: {  # noqa: E731
        "finding_id": fid, "severity": "CRITICAL",
        "title": "FIXTURE staged tool",
        "claims": [{"type": "hash", "sha1": shared,
                    "filename": "FIXTURE_tool.exe"}],
    }
    return {
        "confirmed_malicious_atomic": [mk("FIXTURE_F1"), mk("FIXTURE_F2"),
                                       mk("FIXTURE_F3")],
        "suspicious_needs_review": [],
        "benign_or_false_positive": [],
        "inconclusive_unresolved": [],
        "synthesis_narrative": [],
    }


def test_entity_disposition_buckets_shape_and_dedup():
    parts = E.entity_disposition_buckets(_confirmed_dup_buckets())
    assert set(parts.keys()) == set(E.ENTITY_BUCKETS)
    conf = parts["confirmed_malicious_atomic"]
    assert len(conf) == 1  # 3 dup findings -> 1 entity
    obj = conf[0]
    for fld in ("entity_key", "scope", "source_finding_ids",
                "source_buckets", "claim_entity_keys", "title",
                "routing_decision", "tiebreaker_required"):
        assert fld in obj, fld
    assert sorted(obj["source_finding_ids"]) == [
        "FIXTURE_F1", "FIXTURE_F2", "FIXTURE_F3"]
    assert obj["source_buckets"] == ["confirmed_malicious_atomic"]
    assert obj["scope"] in (
        "file", "process", "network", "chain", "finding", "unknown")
    assert obj["tiebreaker_required"] is False


def test_entity_compression_summary_accepts_dict_run():
    # No state_dir -> empty buckets; function must not raise and must
    # return the full schema with a gates map.
    summ = E.entity_compression_summary({"state_dir": "/nonexistent_xyz"})
    assert summ["finding_count"] == 0
    assert summ["confirmed_atomic_finding_count"] == 0
    assert set(summ["gates"].keys()) == {
        "ENTITY_GROUPING_GATE",
        "CONFIRMED_ATOMIC_ENTITY_DEDUP_GATE",
        "ENTITY_COMPRESSION_RATIO_GATE",
        "ENTITY_CONTRADICTION_BLOCKS_CONFIRMED_GATE",
        "EXISTING_RUN_ENTITY_COMPRESSION_GATE",
        "EXISTING_RUN_CONTRADICTED_ENTITY_ROUTING_GATE",
    }
    assert "entity_disposition_counts" in summ


_DEFAULT_RUN_JSON = "reports/run_20260516_053446.json"


def test_entity_compression_summary_existing_run_gates():
    run_json = os.environ.get("SIFT_DIAGNOSTIC_RUN_JSON",
                              _DEFAULT_RUN_JSON)
    rp = Path(run_json)
    if not rp.is_file():
        pytest.skip("recorded run JSON not present")
    run = json.loads(rp.read_text(errors="ignore"))
    if not (Path(run.get("state_dir", "")) /
            "finding_disposition_buckets.json").is_file():
        pytest.skip("recorded state_dir/buckets not present")

    summ = E.entity_compression_summary(run_json)
    assert summ["confirmed_atomic_finding_count"] == 3
    assert 0 < summ["confirmed_atomic_entity_count"] <= 2
    assert summ["confirmed_atomic_compression_ratio"] <= 0.70
    assert summ["contradicted_entity_count"] >= 4
    assert summ["contradicted_confirmed_entity_count"] == 0
    for gate, status in summ["gates"].items():
        assert status == "PASS", "%s=%s" % (gate, status)
