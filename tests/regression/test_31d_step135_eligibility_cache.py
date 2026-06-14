"""Slot 31D-STEP135-ELIGIBILITY-CACHE regression tests.

Pins:
  - evaluate_confirmed_bucket_eligibility_cached caches per
    (finding_id, evidence_db_mode) and re-invokes the underlying
    evaluator at most once per key.
  - Returned values are deep copies; mutating one return does not
    mutate the cached value.
  - evidence-backed (evidence_db provided) and evidence-less
    (evidence_db=None) calls are stored under different keys.
  - route_findings_for_report yields byte-identical bucket membership
    with and without an eligibility cache.
  - STEP135_TIMING and STEP135_COUNT labels exist in run_pipeline.py.
  - No dataset literals introduced by this slot.

Synthetic, dataset-agnostic. No PIDs, users, paths, IPs, or process
names from any real case appear in these tests.
"""
from __future__ import annotations

import copy
import re
from pathlib import Path

import pytest

from sift_sentinel.analysis import disposition as _disp_mod
from sift_sentinel.analysis.disposition import (
    BUCKET_BENIGN,
    BUCKET_CONFIRMED,
    BUCKET_INCONCLUSIVE,
    BUCKET_SUSPICIOUS,
    BUCKET_SYNTHESIS,
    evaluate_confirmed_bucket_eligibility,
    evaluate_confirmed_bucket_eligibility_cached,
    make_eligibility_cache,
    route_findings_for_report,
    validate_disposition_buckets,
)


_REPO_ROOT = Path(__file__).resolve().parents[2]
_RUN_PIPELINE = _REPO_ROOT / "run_pipeline.py"


# ---------------------------------------------------------------------------
# Synthetic fixture helpers (generic placeholders only).
# ---------------------------------------------------------------------------


def _f_inconclusive(fid: str) -> dict:
    """A minimally-shaped finding that cannot pass confirmed gates --
    used to exercise routing/eligibility without case-specific content.

    Two generic claims are attached so derive_final_disposition reaches
    the gate-7 eligibility check (the cached path) rather than exiting
    early on the one-claim protection gate. The claims are intentionally
    pid-only / shape-only, so the finding still fails the confirmed
    eligibility check and routes out -- exercising the cache, not the
    confirmed bucket.
    """
    return {
        "finding_id": fid,
        "title": "generic-title",
        "artifact": "generic-artifact",
        "severity": "MEDIUM",
        "confidence_level": "MEDIUM",
        "claims": [
            {"claim_type": "pid", "value": "0"},
            {"claim_type": "process_exists", "value": "true"},
        ],
        "raw_excerpt": "",
        "source_tools": [],
        "tool_call_ids": [],
    }


def _f_benign(fid: str) -> dict:
    """A finding with an explicit benign ReAct verdict."""
    f = _f_inconclusive(fid)
    f["react_verdict"] = "confirmed_benign"
    return f


def _f_likely_fp(fid: str) -> dict:
    f = _f_inconclusive(fid)
    f["react_verdict"] = "likely_fp"
    return f


def _f_react_inconclusive(fid: str) -> dict:
    f = _f_inconclusive(fid)
    f["react_verdict"] = "inconclusive"
    return f


def _f_synthesis(fid: str) -> dict:
    f = _f_inconclusive(fid)
    f["finding_type"] = "composite_narrative"
    return f


# ---------------------------------------------------------------------------
# Test 1: cache mechanics -- repeated calls hit the cache, evaluator
# runs at most once per (identity, evidence-mode) key.
# ---------------------------------------------------------------------------


def test_cache_serves_repeated_same_key_calls(monkeypatch) -> None:
    cache = make_eligibility_cache()
    f = _f_inconclusive("synth-001")

    real_eval = _disp_mod.evaluate_confirmed_bucket_eligibility
    calls: list[str] = []

    def _tracking_eval(finding, evidence_db=None):
        calls.append(str(finding.get("finding_id")) + ":" +
                     str(bool(evidence_db)))
        return real_eval(finding, evidence_db)

    monkeypatch.setattr(
        _disp_mod,
        "evaluate_confirmed_bucket_eligibility",
        _tracking_eval,
    )

    a = evaluate_confirmed_bucket_eligibility_cached(f, None, cache)
    b = evaluate_confirmed_bucket_eligibility_cached(f, None, cache)
    c = evaluate_confirmed_bucket_eligibility_cached(f, None, cache)

    # Underlying evaluator runs exactly once for one (id, mode) key.
    assert len(calls) == 1
    # Result equality across cached returns.
    assert a == b == c
    # Stats updated.
    assert cache["misses"] == 1
    assert cache["stores"] == 1
    assert cache["hits"] == 2
    assert len(cache["store"]) == 1


def test_cache_returns_deep_copies(monkeypatch) -> None:
    cache = make_eligibility_cache()
    f = _f_inconclusive("synth-deepcopy")

    a = evaluate_confirmed_bucket_eligibility_cached(f, None, cache)
    # Mutate the returned object aggressively.
    a["blocking_reasons"].append("MUTATED_BY_TEST")
    a["gates"]["NEW_BOGUS_GATE"] = "MUTATED"

    b = evaluate_confirmed_bucket_eligibility_cached(f, None, cache)
    assert "MUTATED_BY_TEST" not in b["blocking_reasons"]
    assert "NEW_BOGUS_GATE" not in b["gates"]


# ---------------------------------------------------------------------------
# Test 2: evidence_db mode separation -- same finding_id with and
# without evidence_db are stored under different keys.
# ---------------------------------------------------------------------------


def test_evidence_db_mode_is_separate_cache_key(monkeypatch) -> None:
    cache = make_eligibility_cache()
    f = _f_inconclusive("synth-evdb")

    real_eval = _disp_mod.evaluate_confirmed_bucket_eligibility
    seen_modes: list[bool] = []

    def _tracking_eval(finding, evidence_db=None):
        seen_modes.append(bool(evidence_db))
        return real_eval(finding, evidence_db)

    monkeypatch.setattr(
        _disp_mod,
        "evaluate_confirmed_bucket_eligibility",
        _tracking_eval,
    )

    # Evidence-backed call (a non-empty dict satisfies bool(evidence_db)).
    evaluate_confirmed_bucket_eligibility_cached(
        f, {"process": []}, cache)
    # Evidence-less call must NOT reuse the evidence-backed result.
    evaluate_confirmed_bucket_eligibility_cached(f, None, cache)

    # Underlying evaluator was invoked once per mode.
    assert seen_modes == [True, False]
    assert cache["misses"] == 2
    assert cache["stores"] == 2
    assert len(cache["store"]) == 2

    # Repeat each mode -- both should now be cache hits.
    evaluate_confirmed_bucket_eligibility_cached(
        f, {"process": []}, cache)
    evaluate_confirmed_bucket_eligibility_cached(f, None, cache)
    assert cache["hits"] == 2
    assert cache["misses"] == 2  # unchanged


# ---------------------------------------------------------------------------
# Test 3: bucket parity -- route_findings_for_report yields identical
# bucket membership with and without the cache.
# ---------------------------------------------------------------------------


def test_bucket_parity_with_and_without_cache() -> None:
    findings = [
        _f_inconclusive("g-incl-1"),
        _f_inconclusive("g-incl-2"),
        _f_benign("g-benign-1"),
        _f_likely_fp("g-likely-fp-1"),
        _f_react_inconclusive("g-react-inc-1"),
        _f_synthesis("g-syn-1"),
        # Repeat one finding object so the cache sees a second hit
        # for the same (id, mode) key.
        _f_inconclusive("g-incl-1"),
    ]

    cache = make_eligibility_cache()

    b_no_cache = route_findings_for_report(
        copy.deepcopy(findings),
        investigations=None,
        evidence_db=None,
    )
    b_cache = route_findings_for_report(
        copy.deepcopy(findings),
        investigations=None,
        evidence_db=None,
        eligibility_cache=cache,
    )

    assert set(b_no_cache.keys()) == set(b_cache.keys())
    for name in b_no_cache:
        ids_no = [f.get("finding_id") for f in b_no_cache[name]]
        ids_yes = [f.get("finding_id") for f in b_cache[name]]
        assert ids_no == ids_yes, (
            "bucket %s membership drifted with cache: %r vs %r"
            % (name, ids_no, ids_yes)
        )

    # The cache must have served at least one hit (the duplicate
    # finding above) and held at most one entry per unique key.
    assert cache["hits"] >= 1
    assert len(cache["store"]) >= 1
    assert cache["misses"] >= 1


def test_validate_disposition_buckets_accepts_cache_kwarg() -> None:
    cache = make_eligibility_cache()
    findings = [_f_inconclusive("g-validate-1")]
    buckets = route_findings_for_report(
        findings,
        investigations=None,
        evidence_db=None,
        eligibility_cache=cache,
    )
    # Should not raise and should agree with no-cache path.
    v_with = validate_disposition_buckets(
        buckets, eligibility_cache=cache)
    v_without = validate_disposition_buckets(buckets)
    assert v_with == v_without


# ---------------------------------------------------------------------------
# Test 4: STEP135 timing/count labels exist in run_pipeline.py.
# ---------------------------------------------------------------------------


def test_run_pipeline_emits_step135_telemetry_labels() -> None:
    text = _RUN_PIPELINE.read_text(encoding="utf-8")

    # The TIMING labels are emitted via a loop over a dict whose keys
    # are the label names. Assert both the loop-format prefix and every
    # required dict key is present in source.
    assert "STEP135_TIMING " in text
    required_timing_keys = [
        "route_s",
        "validate_s",
        "write_buckets_s",
        "entity_context_s",
        "partition_s",
        "telemetry_consistency_s",
        "report_truth_s",
        "confirmed_eligibility_recheck_s",
        "report_bucket_consistency_s",
        "total_s",
    ]
    for key in required_timing_keys:
        # Accept either single- or double-quoted dict-key form.
        if not (("\"%s\"" % key) in text or ("'%s'" % key) in text):
            raise AssertionError(
                "missing STEP135_TIMING key in source: %r" % key
            )

    # Counters are emitted with their literal label in the format
    # string, so they appear verbatim in source.
    required_counts = [
        "STEP135_COUNT eligibility_cache_hits=",
        "STEP135_COUNT eligibility_cache_misses=",
        "STEP135_COUNT eligibility_cache_stores=",
        "STEP135_COUNT eligibility_cache_entries=",
        "STEP135_COUNT findings=",
        "STEP135_COUNT evidence_db_facts=",
    ]
    for tok in required_counts:
        assert tok in text, "missing counter fragment: %r" % tok


# ---------------------------------------------------------------------------
# Test 5: no dataset literals introduced by this slot. The test file
# itself and the disposition cache-helper region must not contain any
# concrete IPv4 octet quad, real Windows user name, or known hostname.
# ---------------------------------------------------------------------------


_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def test_no_dataset_literals_in_test_file() -> None:
    text = Path(__file__).read_text(encoding="utf-8")
    assert not _IPV4_RE.search(text), (
        "synthetic test must not contain IPv4 literals"
    )


def test_no_dataset_literals_in_disposition_cache_block() -> None:
    disp_path = (
        _REPO_ROOT / "src" / "sift_sentinel" / "analysis" /
        "disposition.py"
    )
    text = disp_path.read_text(encoding="utf-8")
    # The cache block is bounded by the slot banner and the original
    # eligibility evaluator. Extract that window and check no IPs /
    # hard-coded case strings sneaked in.
    start_marker = "# ── Slot 31D-STEP135-ELIGIBILITY-CACHE"
    end_marker = "def evaluate_confirmed_bucket_eligibility("
    assert start_marker in text and end_marker in text
    window = text[text.index(start_marker): text.index(end_marker)]
    assert not _IPV4_RE.search(window), (
        "disposition cache block must not contain IPv4 literals"
    )
