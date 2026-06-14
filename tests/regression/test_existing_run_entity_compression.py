"""Slot 31F-alpha TASK 7/8 -- existing-run diagnostic proof (no API).

Static gate-string coverage (ENTITY_GATE_TEST_COVERAGE_GATE):

  EXISTING_RUN_ENTITY_COMPRESSION_GATE
  EXISTING_RUN_CONTRADICTED_ENTITY_ROUTING_GATE

Loads SIFT_DIAGNOSTIC_RUN_JSON (or the default recorded run JSON), its
state_dir, finding_disposition_buckets.json, and reconstructs 5d-alpha
ReAct conflicts from the recorded ReAct turns. Thresholds are
pre-committed; the proven values are derived from the recorded data,
never hardcoded IDs. Skips cleanly if the recorded state_dir is no
longer present (dataset-agnostic).
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from sift_sentinel.entities import (
    EXISTING_RUN_CONTRADICTED_ENTITY_ROUTING_GATE,
    EXISTING_RUN_ENTITY_COMPRESSION_GATE,
    build_entity_truth,
)
from sift_sentinel.react_verdicts import (
    build_react_entity_verdict_ledger,
    detect_react_entity_contradictions,
    extract_react_verdicts,
)

# Pre-committed expectations (thresholds, not data).
EXPECTED_CONFIRMED_ENTITY_COUNT_MAX = 2
EXPECTED_CONTRADICTED_ENTITY_COUNT_MIN = 4
EXPECTED_CONFIRMED_COMPRESSION_RATIO_MAX = 0.70

_DEFAULT_RUN_JSON = "reports/run_20260516_053446.json"


def test_gate_identifiers_static_coverage():
    # ENTITY_GATE_TEST_COVERAGE_GATE: the two existing-run gate strings
    # must be explicitly referenced by this test module.
    assert EXISTING_RUN_ENTITY_COMPRESSION_GATE == \
        "EXISTING_RUN_ENTITY_COMPRESSION_GATE"
    assert EXISTING_RUN_CONTRADICTED_ENTITY_ROUTING_GATE == \
        "EXISTING_RUN_CONTRADICTED_ENTITY_ROUTING_GATE"


def _load_recorded():
    run_json = os.environ.get("SIFT_DIAGNOSTIC_RUN_JSON",
                              _DEFAULT_RUN_JSON)
    rp = Path(run_json)
    if not rp.is_file():
        pytest.skip("recorded run JSON not present: %s" % run_json)
    run = json.loads(rp.read_text(errors="ignore"))
    sd = Path(run.get("state_dir", ""))
    if not sd.is_dir():
        pytest.skip("recorded state_dir not present: %s" % sd)
    bpath = sd / "finding_disposition_buckets.json"
    if not bpath.is_file():
        pytest.skip("finding_disposition_buckets.json not present")
    buckets = json.loads(bpath.read_text(errors="ignore"))
    records = extract_react_verdicts(sd)
    ledger = build_react_entity_verdict_ledger(records)
    conflicts = detect_react_entity_contradictions(ledger)
    return buckets, conflicts


def test_existing_run_confirmed_entity_compression():
    buckets, conflicts = _load_recorded()
    et = build_entity_truth(buckets, react_conflicts=conflicts)

    fc = et["confirmed_atomic_finding_count"]
    ec = et["confirmed_atomic_entity_count"]
    ratio = et["confirmed_atomic_compression_ratio"]

    assert fc > 0, "diagnostic run has confirmed atomic findings"
    assert ec > 0, "confirmed atomic findings must produce entities"
    assert et["confirmed_compression_ok"] is True
    assert ec <= EXPECTED_CONFIRMED_ENTITY_COUNT_MAX
    assert ratio is not None
    assert ratio <= EXPECTED_CONFIRMED_COMPRESSION_RATIO_MAX
    assert ec < fc  # compression actually happened

    print("EXISTING_RUN_CONFIRMED_ATOMIC_FINDING_COUNT=%d" % fc)
    print("EXISTING_RUN_CONFIRMED_ATOMIC_ENTITY_COUNT=%d" % ec)
    print("EXISTING_RUN_CONFIRMED_ATOMIC_COMPRESSION_RATIO=%s" % ratio)
    print("EXISTING_RUN_ENTITY_COMPRESSION_GATE=PASS")


def test_existing_run_contradicted_entities_preserved_and_routed_out():
    buckets, conflicts = _load_recorded()
    et = build_entity_truth(buckets, react_conflicts=conflicts)

    contradicted = [
        e for v in et["buckets"].values() for e in v
        if e.get("has_react_conflict")
    ]
    assert et["contradicted_entity_count"] == len(contradicted)
    assert et["contradicted_entity_count"] >= \
        EXPECTED_CONTRADICTED_ENTITY_COUNT_MIN
    for e in contradicted:
        assert e["tiebreaker_required"] is True
        assert e["entity_disposition"] == "suspicious_needs_review"
        assert e["recommended_entity_disposition"] == \
            "suspicious_needs_review"

    # No contradicted entity leaks into the confirmed entity bucket.
    assert et["contradicted_confirmed_entity_count"] == 0
    conf = et["buckets"]["confirmed_malicious_atomic"]
    for e in conf:
        assert e.get("has_react_conflict") is False
    conflicted_fids: set[str] = set()
    for c in conflicts:
        for cv in c.get("conflicting_verdicts") or []:
            conflicted_fids.update(
                str(x) for x in (cv.get("source_finding_ids") or []))
    conf_fids = {
        fid for e in conf for fid in e["source_finding_ids"]
    }
    assert conf_fids.isdisjoint(conflicted_fids)

    print("EXISTING_RUN_CONTRADICTED_ENTITY_COUNT=%d"
          % et["contradicted_entity_count"])
    print("EXISTING_RUN_CONTRADICTED_CONFIRMED_ENTITY_COUNT=%d"
          % et["contradicted_confirmed_entity_count"])
    print("EXISTING_RUN_CONTRADICTED_ENTITY_ROUTING_GATE=PASS")
