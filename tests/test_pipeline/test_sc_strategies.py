"""Tests for graduated self-correction strategies (attempt-specific prompts)."""

from __future__ import annotations

import logging

import pytest

from sift_sentinel.correction.self_correct import self_correct, STRATEGIES


def _minimal_ref_set():
    """Ref set with one PID entry for validation."""
    return {
        "pids": {9001: {"name": "sample_payload.exe", "source": "vol_pstree"}},
    }


def _minimal_raw_data():
    return {
        "vol_pstree": {
            "output": [
                {"PID": 9001, "ImageFileName": "sample_payload.exe",
                 "CreateTime": "2018-08-30T22:15:18+00:00", "__children": []},
            ],
        },
    }


class TestSCAttempt1IncludesReason:
    """Attempt 1 prompt contains the rejection reason."""

    def test_sc_attempt1_includes_reason(self):
        prompts_received = []

        def capture_corrector(raw_data, prompt):
            prompts_received.append(prompt)
            return None

        self_correct(
            finding={"finding_id": "F001", "claims": []},
            error="PID 999 not found in reference set",
            raw_data=_minimal_raw_data(),
            ref_set=_minimal_ref_set(),
            max_attempts=1,
            corrector_fn=capture_corrector,
        )
        assert len(prompts_received) == 1
        assert "PID 999 not found in reference set" in prompts_received[0]
        assert "REJECTED" in prompts_received[0]


class TestSCAttempt2Simplifies:
    """Attempt 2 prompt directs PID-only claims."""

    def test_sc_attempt2_simplifies(self):
        prompts_received = []

        def capture_corrector(raw_data, prompt):
            prompts_received.append(prompt)
            return None

        self_correct(
            finding={"finding_id": "F001", "claims": []},
            error="claim mismatch",
            raw_data=_minimal_raw_data(),
            ref_set=_minimal_ref_set(),
            max_attempts=2,
            corrector_fn=capture_corrector,
        )
        assert len(prompts_received) == 2
        assert "PID-based claims" in prompts_received[1]
        assert "vol_pstree" in prompts_received[1]


class TestSCAttempt3AllowsDrop:
    """Attempt 3 prompt mentions drop action."""

    def test_sc_attempt3_allows_drop(self):
        prompts_received = []

        def capture_corrector(raw_data, prompt):
            prompts_received.append(prompt)
            return None

        self_correct(
            finding={"finding_id": "F001", "claims": []},
            error="claim mismatch",
            raw_data=_minimal_raw_data(),
            ref_set=_minimal_ref_set(),
            max_attempts=3,
            corrector_fn=capture_corrector,
        )
        assert len(prompts_received) == 3
        assert "drop" in prompts_received[2].lower()
        assert "action" in prompts_received[2].lower()


class TestSCDropMarksInconclusive:
    """Drop response from corrector marks finding INCONCLUSIVE."""

    def test_sc_drop_marks_inconclusive(self):
        call_count = 0

        def drop_on_attempt3(raw_data, prompt):
            nonlocal call_count
            call_count += 1
            if call_count >= 3:
                return {"finding_id": "F001", "action": "drop"}
            return None

        result = self_correct(
            finding={"finding_id": "F001", "claims": []},
            error="claim mismatch",
            raw_data=_minimal_raw_data(),
            ref_set=_minimal_ref_set(),
            max_attempts=3,
            corrector_fn=drop_on_attempt3,
        )
        assert result["status"] == "UNRESOLVED"
        f = result["finding"]
        assert f["confidence_level"] == "INCONCLUSIVE"
        assert "3 correction attempts" in f.get("correction_reason", "")


class TestSCStrategiesLogged:
    """Each strategy name appears in log output."""

    def test_sc_strategies_logged(self, caplog):
        def noop(raw_data, prompt):
            return None

        with caplog.at_level(logging.INFO):
            self_correct(
                finding={"finding_id": "F001", "claims": []},
                error="claim mismatch",
                raw_data=_minimal_raw_data(),
                ref_set=_minimal_ref_set(),
                max_attempts=3,
                corrector_fn=noop,
            )
        log_text = caplog.text
        assert "Explain and retry" in log_text
        assert "Simplify" in log_text
        assert "Last chance" in log_text
