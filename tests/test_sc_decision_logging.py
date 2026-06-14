"""P0-B regression: SC DECISION must fire on every SC path.

_f4_log_decision already existed before P0-B; this suite locks in that
it now fires on:
  1. attempt-level error branches that previously short-circuited silently
     (None return, non-dict return, exception, rate-limited retry failure,
     unfixable wrapper, non-dict wrapper)
  2. every terminal return with action=correction_complete
     (outcomes: CORRECTED, DROPPED_UNSUPPORTED, EXHAUSTED, DROPPED_HONEST)
  3. post-validation outcomes (validator rejected a revision)

Also locks in result["outcome_kind"] for each terminal path so
run_pipeline.py can honestly bucket results into corrected / contained /
errored counts without mislabeling containment as success.
"""

from __future__ import annotations

import logging

import pytest

from sift_sentinel.correction.self_correct import (
    self_correct,
    _f4_log_decision,
)
from sift_sentinel.validation.reference_set import build_reference_set


# ── fixtures ─────────────────────────────────────────────────────────────

_RAW_DATA = {
    "vol_pstree": {
        "output": [
            {"PID": 9001, "ImageFileName": "sample_payload.exe",
             "CreateTime": "2018-08-30T22:15:18+00:00", "__children": []},
        ],
    },
}

_REF_SET = build_reference_set(_RAW_DATA)


def _ref_set():
    return _REF_SET


def _raw_data():
    return _RAW_DATA


def _blocked_finding():
    return {"finding_id": "F_TEST", "claims": []}


# ── _f4_log_decision signature -- override kwargs ────────────────────────

def test_f4_log_decision_accepts_explicit_override(caplog):
    """Callers can supply action/outcome/reason directly when the
    AI response is absent or not classifiable."""
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="sift_sentinel.correction.self_correct"):
        _f4_log_decision(
            "F_X", 2, None, "validator error text",
            action="corrector_returned_none", outcome="ERROR",
            reason="corrector returned None",
        )
    assert "SC DECISION F_X" in caplog.text
    assert "attempt=2" in caplog.text
    assert "action=corrector_returned_none" in caplog.text
    assert "validator_result=ERROR" in caplog.text
    assert "corrector returned None" in caplog.text


def test_f4_log_decision_autoclassifies_when_no_override(caplog):
    """Omitting overrides preserves the original auto-classify behavior
    (regression guard: existing callers must keep working)."""
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="sift_sentinel.correction.self_correct"):
        _f4_log_decision(
            "F_Y", 1,
            {"claims": [{"pid": 9001}]},
            "",
        )
    assert "SC DECISION F_Y" in caplog.text
    assert "PROPOSED_REWRITE_PENDING_VALIDATION" in caplog.text


# ── attempt-level branches that were silent pre-P0-B ─────────────────────

def test_sc_decision_logs_when_corrector_returns_none(caplog):
    def noop(raw_data, prompt):
        return None

    caplog.clear()
    with caplog.at_level(logging.INFO, logger="sift_sentinel.correction.self_correct"):
        self_correct(
            finding=_blocked_finding(),
            error="claim mismatch",
            raw_data=_raw_data(),
            ref_set=_ref_set(),
            max_attempts=1,
            corrector_fn=noop,
        )
    assert "SC DECISION F_TEST" in caplog.text
    assert "action=corrector_returned_none" in caplog.text


def test_sc_decision_logs_when_corrector_returns_non_dict(caplog):
    def returns_list(raw_data, prompt):
        return []  # wrong shape

    caplog.clear()
    with caplog.at_level(logging.INFO, logger="sift_sentinel.correction.self_correct"):
        self_correct(
            finding=_blocked_finding(),
            error="claim mismatch",
            raw_data=_raw_data(),
            ref_set=_ref_set(),
            max_attempts=1,
            corrector_fn=returns_list,
        )
    assert "SC DECISION F_TEST" in caplog.text
    assert "action=non_dict_return" in caplog.text


def test_sc_decision_logs_when_corrector_raises(caplog):
    def raises(raw_data, prompt):
        raise RuntimeError("backend offline")

    caplog.clear()
    with caplog.at_level(logging.INFO, logger="sift_sentinel.correction.self_correct"):
        self_correct(
            finding=_blocked_finding(),
            error="claim mismatch",
            raw_data=_raw_data(),
            ref_set=_ref_set(),
            max_attempts=1,
            corrector_fn=raises,
        )
    assert "SC DECISION F_TEST" in caplog.text
    assert "action=exception" in caplog.text
    assert "backend offline" in caplog.text


def test_sc_decision_logs_when_rate_limited_twice(caplog):
    def rate_limited(raw_data, prompt):
        raise RuntimeError("429 rate_limit exceeded")

    caplog.clear()
    with caplog.at_level(logging.INFO, logger="sift_sentinel.correction.self_correct"):
        self_correct(
            finding=_blocked_finding(),
            error="claim mismatch",
            raw_data=_raw_data(),
            ref_set=_ref_set(),
            max_attempts=1,
            corrector_fn=rate_limited,
            rate_limit_wait=0.0,
        )
    assert "SC DECISION F_TEST" in caplog.text
    assert "action=rate_limited" in caplog.text


def test_sc_decision_logs_when_wrapper_declares_unfixable(caplog):
    def wrapper_null(raw_data, prompt):
        return {"reasoning": "evidence does not support this claim",
                "finding": None}

    caplog.clear()
    with caplog.at_level(logging.INFO, logger="sift_sentinel.correction.self_correct"):
        self_correct(
            finding=_blocked_finding(),
            error="claim mismatch",
            raw_data=_raw_data(),
            ref_set=_ref_set(),
            max_attempts=1,
            corrector_fn=wrapper_null,
        )
    assert "SC DECISION F_TEST" in caplog.text
    assert "action=declared_unfixable" in caplog.text
    assert "validator_result=UNFIXABLE" in caplog.text


def test_sc_decision_logs_when_wrapper_finding_is_non_dict(caplog):
    def wrapper_bad(raw_data, prompt):
        return {"reasoning": "x", "finding": "not-a-dict"}

    caplog.clear()
    with caplog.at_level(logging.INFO, logger="sift_sentinel.correction.self_correct"):
        self_correct(
            finding=_blocked_finding(),
            error="claim mismatch",
            raw_data=_raw_data(),
            ref_set=_ref_set(),
            max_attempts=1,
            corrector_fn=wrapper_bad,
        )
    assert "SC DECISION F_TEST" in caplog.text
    assert "action=non_dict_wrapper" in caplog.text


# ── terminal SC DECISION with action=correction_complete ─────────────────

def test_terminal_sc_decision_correction_complete_exhausted(caplog):
    """All attempts failed because AI never produced a classifiable
    response -> terminal outcome=DROPPED_HONEST with action=correction_complete."""
    def noop(raw_data, prompt):
        return None

    caplog.clear()
    with caplog.at_level(logging.INFO, logger="sift_sentinel.correction.self_correct"):
        result = self_correct(
            finding=_blocked_finding(),
            error="claim mismatch",
            raw_data=_raw_data(),
            ref_set=_ref_set(),
            max_attempts=3,
            corrector_fn=noop,
            inter_attempt_delay=0.0,
        )
    assert "action=correction_complete" in caplog.text
    assert "validator_result=DROPPED_HONEST" in caplog.text
    assert result["outcome_kind"] == "DROPPED_HONEST"
    assert result["status"] == "UNRESOLVED"


def test_terminal_sc_decision_dropped_unsupported(caplog):
    """AI returns drop action -> terminal outcome=DROPPED_UNSUPPORTED."""
    def drop_immediately(raw_data, prompt):
        return {"finding_id": "F_TEST", "action": "drop"}

    caplog.clear()
    with caplog.at_level(logging.INFO, logger="sift_sentinel.correction.self_correct"):
        result = self_correct(
            finding=_blocked_finding(),
            error="claim mismatch",
            raw_data=_raw_data(),
            ref_set=_ref_set(),
            max_attempts=3,
            corrector_fn=drop_immediately,
            inter_attempt_delay=0.0,
        )
    assert "action=correction_complete" in caplog.text
    assert "validator_result=DROPPED_UNSUPPORTED" in caplog.text
    assert result["outcome_kind"] == "DROPPED_UNSUPPORTED"
    assert result["finding"]["confidence_level"] == "INCONCLUSIVE"


def test_terminal_sc_decision_corrected(caplog):
    """Validator passes the revision -> terminal outcome=CORRECTED."""
    def returns_valid(raw_data, prompt):
        return {
            "finding_id": "F_TEST",
            "artifact": "sample_payload.exe",
            "claims": [
                {"type": "pid", "pid": 9001, "process": "sample_payload.exe",
                 "source_tools": ["vol_pstree"]},
            ],
        }

    caplog.clear()
    with caplog.at_level(logging.INFO, logger="sift_sentinel.correction.self_correct"):
        result = self_correct(
            finding=_blocked_finding(),
            error="claim mismatch",
            raw_data=_raw_data(),
            ref_set=_ref_set(),
            max_attempts=1,
            corrector_fn=returns_valid,
        )
    assert result["status"] == "CORRECTED", (
        f"validator rejected the revision: status={result['status']} "
        f"attempts={result.get('attempts')}"
    )
    assert "action=correction_complete" in caplog.text
    assert "validator_result=CORRECTED" in caplog.text
    assert result["outcome_kind"] == "CORRECTED"


def test_terminal_sc_decision_exhausted_with_validator_rejection(caplog):
    """AI answers each attempt but validator keeps rejecting -> outcome=EXHAUSTED
    (not DROPPED_HONEST) since every attempt produced a classifiable decision."""
    def always_wrong_pid(raw_data, prompt):
        return {
            "finding_id": "F_TEST",
            "claims": [{"pid": 999999, "source_tools": ["vol_pstree"]}],
        }

    caplog.clear()
    with caplog.at_level(logging.INFO, logger="sift_sentinel.correction.self_correct"):
        result = self_correct(
            finding=_blocked_finding(),
            error="claim mismatch",
            raw_data=_raw_data(),
            ref_set=_ref_set(),
            max_attempts=2,
            corrector_fn=always_wrong_pid,
            inter_attempt_delay=0.0,
        )
    assert "action=correction_complete" in caplog.text
    assert "validator_result=EXHAUSTED" in caplog.text
    assert result["outcome_kind"] == "EXHAUSTED"
    assert result["status"] == "UNRESOLVED"


def test_revalidation_failure_logs_blocked_by_validator(caplog):
    """When corrector answers and validator rejects, a per-attempt
    SC DECISION action=revalidation_failed fires before the next attempt."""
    def always_wrong_pid(raw_data, prompt):
        return {
            "finding_id": "F_TEST",
            "claims": [{"pid": 999999, "source_tools": ["vol_pstree"]}],
        }

    caplog.clear()
    with caplog.at_level(logging.INFO, logger="sift_sentinel.correction.self_correct"):
        self_correct(
            finding=_blocked_finding(),
            error="claim mismatch",
            raw_data=_raw_data(),
            ref_set=_ref_set(),
            max_attempts=1,
            corrector_fn=always_wrong_pid,
            inter_attempt_delay=0.0,
        )
    assert "action=revalidation_failed" in caplog.text
    assert "validator_result=BLOCKED_BY_VALIDATOR" in caplog.text


# ── outcome_kind is always populated ─────────────────────────────────────

@pytest.mark.parametrize(
    "corrector, expected_kind",
    [
        (lambda r, p: None, "DROPPED_HONEST"),
        (lambda r, p: {"finding_id": "F_TEST", "action": "drop"},
         "DROPPED_UNSUPPORTED"),
        (lambda r, p: {"finding_id": "F_TEST",
                       "claims": [{"pid": 999999,
                                   "source_tools": ["vol_pstree"]}]},
         "EXHAUSTED"),
    ],
)
def test_result_has_outcome_kind(corrector, expected_kind):
    """Every terminal path tags the result dict with outcome_kind so
    run_pipeline.py can bucket honest containment vs real errors."""
    result = self_correct(
        finding=_blocked_finding(),
        error="claim mismatch",
        raw_data=_raw_data(),
        ref_set=_ref_set(),
        max_attempts=2,
        corrector_fn=corrector,
        inter_attempt_delay=0.0,
    )
    assert "outcome_kind" in result
    assert result["outcome_kind"] == expected_kind


# ── grep-surface guarantee: SC DECISION count per blocked finding ────────

def test_every_attempt_emits_at_least_one_sc_decision(caplog):
    """Judges grep 'SC DECISION' to audit per-attempt behavior. A run
    of N attempts must produce >= N SC DECISION lines regardless of
    which branch each attempt takes (error / drop / validated / blocked)."""
    def noop(raw_data, prompt):
        return None

    caplog.clear()
    with caplog.at_level(logging.INFO, logger="sift_sentinel.correction.self_correct"):
        self_correct(
            finding=_blocked_finding(),
            error="claim mismatch",
            raw_data=_raw_data(),
            ref_set=_ref_set(),
            max_attempts=3,
            corrector_fn=noop,
            inter_attempt_delay=0.0,
        )
    sc_decision_lines = [
        line for line in caplog.text.splitlines()
        if "SC DECISION F_TEST" in line
    ]
    # 3 attempts = 3 per-attempt SC DECISION lines + 1 terminal line.
    assert len(sc_decision_lines) >= 4


def test_terminal_sc_decision_is_emitted_exactly_once(caplog):
    """One (and only one) action=correction_complete line per self_correct
    call -- lets judges grep '| wc -l' to count blocked findings by
    terminal outcome without double-counting."""
    def noop(raw_data, prompt):
        return None

    caplog.clear()
    with caplog.at_level(logging.INFO, logger="sift_sentinel.correction.self_correct"):
        self_correct(
            finding=_blocked_finding(),
            error="claim mismatch",
            raw_data=_raw_data(),
            ref_set=_ref_set(),
            max_attempts=3,
            corrector_fn=noop,
            inter_attempt_delay=0.0,
        )
    terminal_lines = [
        line for line in caplog.text.splitlines()
        if "action=correction_complete" in line
    ]
    assert len(terminal_lines) == 1
