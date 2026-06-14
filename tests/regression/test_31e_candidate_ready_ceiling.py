"""31E-CANDIDATE-REVIEW-WORTHY-TELEMETRY.

Synthetic-only. Tests the recall-ceiling helper, the review-worthy
selector, and the render-prompt separation. No run_pipeline import,
no real-mount fixtures, no case literals.

The helper must:
- Bucket every non-ready candidate exactly once, with priority
  suppressed > context_type > corroborated_review_worthy > thin.
- Report max_defensible = ready + review_worthy.
- NEVER promote review-worthy candidates to validation_ready.
- Produce deterministic ordering for the review-worthy list.
"""
from __future__ import annotations

import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import sift_sentinel.analysis.candidate_observations as co  # noqa: E402
from sift_sentinel.analysis.candidate_observations import (  # noqa: E402
    _candidate_recall_ceiling,
    _is_review_worthy,
    _select_review_worthy_candidates,
    build_candidate_observations,
    render_candidate_observations_for_prompt,
)


# ── fixtures: synthetic candidate dicts ─────────────────────────────


def _ready(entity: str, score: int = 130) -> dict:
    return {
        "candidate_id": f"cand-{entity}",
        "candidate_type": "suspicious_file_or_process_execution",
        "score": score,
        "entity_key": entity,
        "validation_ready": True,
        "signals": ["multi_source", "multi_fact_type"],
        "source_tools": ["sourceA", "sourceB"],
        "fact_types": ["typeA", "typeB"],
        "fact_ids": ["f1", "f2"],
        "supporting_facts": [],
        "disconfirming_facts": [],
        "suppression_reason": "",
        "claim_templates": [],
    }


def _suppressed(entity: str) -> dict:
    c = _ready(entity, score=90)
    c["validation_ready"] = False
    c["suppression_reason"] = "baseline_service_registry_without_suspicious_imagepath"
    return c


def _context(entity: str, ctype: str = "context_only") -> dict:
    c = _ready(entity, score=70)
    c["validation_ready"] = False
    c["candidate_type"] = ctype
    c["suppression_reason"] = ""
    return c


def _review_worthy(entity: str, score: int = 75) -> dict:
    """Multi-source + multi-fact-type, no suppression, non-context, score>=60."""
    c = _ready(entity, score=score)
    c["validation_ready"] = False
    c["suppression_reason"] = ""
    c["candidate_type"] = "suspicious_file_or_process_execution"
    return c


def _thin_single_source(entity: str) -> dict:
    c = _ready(entity, score=65)
    c["validation_ready"] = False
    c["source_tools"] = ["sourceA"]  # only one source
    c["fact_types"] = ["typeA", "typeB"]
    c["suppression_reason"] = ""
    c["candidate_type"] = "suspicious_file_or_process_execution"
    return c


def _thin_single_fact_type(entity: str) -> dict:
    c = _ready(entity, score=65)
    c["validation_ready"] = False
    c["source_tools"] = ["sourceA", "sourceB"]
    c["fact_types"] = ["typeA"]  # only one fact type
    c["suppression_reason"] = ""
    c["candidate_type"] = "suspicious_file_or_process_execution"
    return c


def _thin_low_score(entity: str) -> dict:
    c = _ready(entity, score=55)  # below 60 threshold
    c["validation_ready"] = False
    c["source_tools"] = ["sourceA", "sourceB"]
    c["fact_types"] = ["typeA", "typeB"]
    c["suppression_reason"] = ""
    c["candidate_type"] = "suspicious_file_or_process_execution"
    return c


# ── 1) recall-ceiling math + bucket invariants ───────────────────────


def test_max_defensible_equals_ready_plus_review_worthy():
    pool = (
        [_ready(f"r{i}") for i in range(7)]
        + [_review_worthy(f"rw{i}") for i in range(4)]
        + [_suppressed(f"sup{i}") for i in range(3)]
        + [_context(f"ctx{i}") for i in range(2)]
        + [_context(f"rdp{i}", ctype="remote_access_context") for i in range(2)]
        + [_thin_single_source(f"ts{i}") for i in range(5)]
        + [_thin_single_fact_type(f"tf{i}") for i in range(3)]
        + [_thin_low_score(f"tl{i}") for i in range(2)]
    )
    res = _candidate_recall_ceiling(pool, returned_validation_ready=7)
    assert res["total_candidates"] == 28
    assert res["validation_ready_total"] == 7
    assert res["returned_validation_ready"] == 7
    assert res["nonready_total"] == 21
    bc = res["nonready_bucket_counts"]
    assert bc["suppressed"] == 3
    assert bc["context_type"] == 4  # 2 context_only + 2 remote_access_context
    assert bc["corroborated_review_worthy"] == 4
    assert bc["thin_single_source_or_type"] == 10  # 5 + 3 + 2
    # Every non-ready candidate is bucketed exactly once.
    assert sum(bc.values()) == res["nonready_total"]
    assert res["review_worthy_count"] == 4
    assert res["max_defensible"] == 7 + 4  # ready + review_worthy


def test_bucket_priority_suppressed_beats_context_and_review():
    """A candidate that is BOTH suppressed AND context-typed counts as suppressed."""
    weird = _suppressed("multi")
    weird["candidate_type"] = "context_only"  # also context
    weird["source_tools"] = ["sourceA", "sourceB"]
    weird["fact_types"] = ["typeA", "typeB"]
    weird["score"] = 90  # would qualify as review-worthy if non-suppressed/non-context
    res = _candidate_recall_ceiling([weird], returned_validation_ready=0)
    bc = res["nonready_bucket_counts"]
    assert bc["suppressed"] == 1
    assert bc["context_type"] == 0
    assert bc["corroborated_review_worthy"] == 0
    assert bc["thin_single_source_or_type"] == 0


def test_bucket_priority_context_beats_review():
    """A non-suppressed context candidate with good corroboration is context, not review."""
    c = _review_worthy("rdpish")
    c["candidate_type"] = "remote_access_context"
    res = _candidate_recall_ceiling([c], returned_validation_ready=0)
    bc = res["nonready_bucket_counts"]
    assert bc["context_type"] == 1
    assert bc["corroborated_review_worthy"] == 0


# ── 2) review-worthy predicate edge cases ────────────────────────────


def test_is_review_worthy_rejects_ready():
    assert _is_review_worthy(_ready("x")) is False


def test_is_review_worthy_rejects_suppressed():
    assert _is_review_worthy(_suppressed("x")) is False


def test_is_review_worthy_rejects_context_types():
    assert _is_review_worthy(_context("x", "context_only")) is False
    assert _is_review_worthy(_context("x", "remote_access_context")) is False


def test_is_review_worthy_rejects_single_source():
    assert _is_review_worthy(_thin_single_source("x")) is False


def test_is_review_worthy_rejects_single_fact_type():
    assert _is_review_worthy(_thin_single_fact_type("x")) is False


def test_is_review_worthy_rejects_low_score():
    assert _is_review_worthy(_thin_low_score("x")) is False


def test_is_review_worthy_score_boundary_60():
    c = _review_worthy("boundary", score=60)
    assert _is_review_worthy(c) is True
    c["score"] = 59
    assert _is_review_worthy(c) is False


# ── 3) deterministic ordering of review-worthy list ──────────────────


def test_review_worthy_ordering_deterministic_across_shuffles():
    pool = (
        [_review_worthy(f"rw-{i:02d}", score=60 + (i % 5) * 10) for i in range(15)]
        + [_thin_single_source(f"ts{i}") for i in range(5)]
        + [_ready(f"r{i}") for i in range(3)]
    )
    canonical = _select_review_worthy_candidates(pool)
    for seed in (1, 7, 42, 1000):
        rng = random.Random(seed)
        shuffled = list(pool)
        rng.shuffle(shuffled)
        out = _select_review_worthy_candidates(shuffled)
        assert [c["entity_key"] for c in out] == [
            c["entity_key"] for c in canonical
        ], f"non-deterministic order under seed {seed}"


def test_review_worthy_ordering_score_descending():
    pool = [
        _review_worthy("low", score=60),
        _review_worthy("hi", score=120),
        _review_worthy("mid", score=85),
    ]
    out = _select_review_worthy_candidates(pool)
    assert [c["entity_key"] for c in out] == ["hi", "mid", "low"]


# ── 4) validation_ready count unchanged + no promotion ───────────────


def test_validation_ready_total_matches_input_pool():
    """The helper must NOT modify candidates and MUST count ready faithfully."""
    pool = [_ready("a"), _ready("b"), _review_worthy("c"), _suppressed("d")]
    res = _candidate_recall_ceiling(pool, returned_validation_ready=2)
    assert res["validation_ready_total"] == 2
    # And no candidate's validation_ready flag was flipped:
    assert sum(1 for c in pool if c.get("validation_ready")) == 2
    assert pool[2].get("validation_ready") is False  # review-worthy stayed False


def test_review_worthy_candidates_never_promoted_to_ready():
    pool = [_review_worthy(f"rw{i}") for i in range(5)] + [_ready(f"r{i}") for i in range(2)]
    out = _select_review_worthy_candidates(pool)
    assert len(out) == 5
    for c in out:
        assert c["validation_ready"] is False, (
            f"review-worthy candidate {c['entity_key']} got validation_ready=True"
        )


# ── 5) build_candidate_observations payload integration ─────────────


def test_payload_carries_ceiling_and_review_worthy_keys():
    """End-to-end through build_candidate_observations with a minimal fact set."""
    evdb = {
        "typed_facts": [
            # Two source tools, two fact types, signal-rich → multi_source/multi_fact_type
            {
                "fact_id": "f1",
                "source_tool": "vol_pslist",
                "fact_type": "process_record",
                "process_name": "rundll32.exe",
                "process_path": "C:\\Users\\Public\\drop\\rundll32.exe",
                "command_line": "rundll32.exe C:\\Users\\Public\\drop\\thing.dll,Run",
            },
            {
                "fact_id": "f2",
                "source_tool": "parse_event_logs",
                "fact_type": "logon_event",
                "process_path": "C:\\Users\\Public\\drop\\rundll32.exe",
            },
        ]
    }
    payload = build_candidate_observations(evdb)
    assert "validation_ready_ceiling" in payload
    assert "corroborated_review_candidates" in payload
    ceiling = payload["validation_ready_ceiling"]
    for key in (
        "total_candidates",
        "validation_ready_total",
        "returned_validation_ready",
        "nonready_total",
        "nonready_bucket_counts",
        "review_worthy_count",
        "max_defensible",
    ):
        assert key in ceiling
    # validation_ready_count in payload must match ceiling's validation_ready_total
    assert (
        payload["validation_ready_count"]
        == ceiling["validation_ready_total"]
    )


def test_render_prompt_section_separates_review_candidates():
    """Rendered prompt has a distinct corroborated_review_candidates section
    that explicitly disclaims validation-ready status."""
    payload = {
        "candidates": [_ready("r1"), _ready("r2")],
        "corroborated_review_candidates": [
            _review_worthy("rw-A"),
            _review_worthy("rw-B"),
        ],
    }
    out = render_candidate_observations_for_prompt(payload)
    assert "Validation-ready candidate conversion rules" in out
    assert "corroborated_review_candidates" in out
    assert "NOT validation-ready" in out or "NOT findings" in out
    # Review-worthy candidate ids appear ONLY in the review section.
    review_marker = out.index("corroborated_review_candidates")
    ready_section = out[:review_marker]
    review_section = out[review_marker:]
    assert "rw-A" not in ready_section
    assert "rw-B" not in ready_section
    assert "rw-A" in review_section
    assert "rw-B" in review_section


def test_render_prompt_handles_no_ready_only_review():
    payload = {
        "candidates": [],
        "corroborated_review_candidates": [_review_worthy("only-rw")],
    }
    out = render_candidate_observations_for_prompt(payload)
    assert "corroborated_review_candidates" in out
    assert "only-rw" in out


def test_render_prompt_handles_no_data():
    assert render_candidate_observations_for_prompt({}) == ""
    assert render_candidate_observations_for_prompt(None) == ""


# ── 6) Helper input robustness ───────────────────────────────────────


def test_helper_handles_empty_pool():
    res = _candidate_recall_ceiling([], returned_validation_ready=0)
    assert res["total_candidates"] == 0
    assert res["max_defensible"] == 0
    assert sum(res["nonready_bucket_counts"].values()) == 0


def test_helper_handles_non_list_input():
    res = _candidate_recall_ceiling(None, returned_validation_ready=0)
    assert res["total_candidates"] == 0


# ── 7) Hard-rule guards on this test file itself ─────────────────────


def test_no_run_pipeline_import():
    text = Path(__file__).read_text(errors="replace")
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("import run_pipeline") or stripped.startswith(
            "from run_pipeline"
        ):
            raise AssertionError(
                f"this test must not depend on run_pipeline (synthetic only): {line!r}"
            )


def test_no_dataset_literals_in_this_test():
    src = Path(__file__).read_text(errors="replace")
    banned = [
        "172." + "16.",
        "td" + "ungan",
        "sp" + "sql",
        "OUT" + "LOOK",
        "base-" + "rd01",
        "squirrel" + "directory",
        "shield" + "base",
        "Wmi" + "PrvSE",
    ]
    for token in banned:
        assert token not in src, f"forbidden dataset literal: {token}"
