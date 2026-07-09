"""
Sentinel Qwen Ensemble - Self-correction rate-limit protection tests.
Validates: context truncation, relevant tool filtering,
inter-attempt delay, and 429 retry logic.
"""

from __future__ import annotations

import copy
import json
from unittest.mock import patch

import pytest

from sift_sentinel.correction.self_correct import (
    _build_sc_context,
    self_correct,
)
from sift_sentinel.validation.validator import validate_finding


# ── Shared fixtures ────────────────────────────────────────────────────────

REF_SET = {
    "hashes": {"abc123def456": "malware.exe"},
    "pid_to_process": {1234: ["svchost.exe"], 9004: ["sample_payload.exe"]},
    "timestamps_per_artifact": {"malware.exe": ["2018-04-11 14:22:07"]},
    "connections": {"9004:192.0.2.111:4444->192.0.2.129:443": "sample_payload.exe"},
    "paths": {},
}

WRONG_FINDING = {
    "finding_id": "F-001",
    "artifact": "malware.exe",
    "confidence_level": "HIGH",
    "claims": [
        {"type": "hash", "sha1": "abc123def456", "filename": "benign.exe"},
    ],
}

CORRECT_FINDING = {
    "finding_id": "F-001",
    "artifact": "malware.exe",
    "confidence_level": "HIGH",
    "claims": [
        {"type": "hash", "sha1": "abc123def456", "filename": "malware.exe"},
    ],
}

RAW_DATA = {
    "vol_pstree": {"output": [{"PID": 9004, "ImageFileName": "sample_payload.exe"}]},
    "get_amcache": {"output": [{"sha1": "abc123def456", "path": "C:\\malware.exe"}]},
}


# ── PART 1: Context truncation tests ──────────────────────────────────────


def test_sc_context_truncation():
    """_build_sc_context with 500K+ input returns < 80K chars."""
    big_outputs = {}
    # 10 tools x 60K chars each = ~600K total
    for i in range(10):
        big_outputs[f"vol_netscan" if i == 0 else f"tool_{i}"] = {
            "data": "x" * 60000,
        }
    finding = {"finding_id": "F-001", "claims": [], "source_tools": []}
    result = _build_sc_context(finding, big_outputs, max_chars=80000)
    result_str = json.dumps(result, default=str)
    assert len(result_str) < 80000


def test_sc_context_includes_relevant_tools():
    """Finding referencing vol_netscan gets netscan data in context."""
    outputs = {
        "vol_netscan": {"connections": [{"local": "1.2.3.4"}]},
        "vol_pstree": {"processes": [{"pid": 1}]},
        "get_amcache": {"entries": []},
    }
    finding = {
        "finding_id": "F-001",
        "claims": [
            {"type": "connection", "source_tools": ["vol_netscan"]},
        ],
    }
    result = _build_sc_context(finding, outputs)
    assert "vol_netscan" in result
    # amcache is a core tool, always included
    assert "get_amcache" in result


def test_sc_context_always_includes_core_tools():
    """Core tools (amcache, prefetch, netscan, event_logs) always included."""
    outputs = {
        "vol_netscan": {"data": "net"},
        "get_amcache": {"data": "amc"},
        "parse_prefetch": {"data": "pf"},
        "parse_event_logs": {"data": "evt"},
        "vol_pstree": {"data": "ps"},
    }
    finding = {"finding_id": "F-001", "claims": []}
    result = _build_sc_context(finding, outputs)
    assert "vol_netscan" in result
    assert "get_amcache" in result
    assert "parse_prefetch" in result
    assert "parse_event_logs" in result
    # Non-core tool with no claim reference is excluded
    assert "vol_pstree" not in result


# ── PART 2: Inter-attempt delay tests ────────────────────────────────────


def test_sc_delay_between_attempts():
    """time.sleep called between attempts with inter_attempt_delay."""
    with patch(
        "sift_sentinel.correction.self_correct.time.sleep",
    ) as mock_sleep:
        self_correct(
            finding=WRONG_FINDING,
            error="hash mismatch",
            raw_data=RAW_DATA,
            ref_set=REF_SET,
            corrector_fn=lambda rd, e: copy.deepcopy(WRONG_FINDING),
            inter_attempt_delay=5.0,
        )

        # Should have called sleep(5.0) before attempts 2 and 3
        delay_calls = [
            c for c in mock_sleep.call_args_list
            if c[0][0] == 5.0
        ]
        assert len(delay_calls) == 2


# ── PART 3: Rate-limit retry tests ──────────────────────────────────────


def test_sc_rate_limit_retry():
    """429 error triggers wait and successful retry."""
    call_count = [0]

    def rate_limited_then_ok(raw_data, error):
        call_count[0] += 1
        if call_count[0] == 1:
            raise Exception("Error: 429 rate_limit_exceeded")
        return copy.deepcopy(CORRECT_FINDING)

    with patch(
        "sift_sentinel.correction.self_correct.time.sleep",
    ) as mock_sleep:
        result = self_correct(
            finding=WRONG_FINDING,
            error="hash mismatch",
            raw_data=RAW_DATA,
            ref_set=REF_SET,
            corrector_fn=rate_limited_then_ok,
            rate_limit_wait=60.0,
        )

        # Should have waited 60s on rate limit
        rate_wait_calls = [
            c for c in mock_sleep.call_args_list
            if c[0][0] == 60.0
        ]
        assert len(rate_wait_calls) >= 1
        # Retry succeeded
        assert result["status"] == "CORRECTED"


def test_sc_rate_limit_both_fail():
    """429 on both original and retry → RATE_LIMITED status in attempts."""
    def always_429(raw_data, error):
        raise Exception("429 Too Many Requests")

    with patch(
        "sift_sentinel.correction.self_correct.time.sleep",
    ):
        result = self_correct(
            finding=WRONG_FINDING,
            error="hash mismatch",
            raw_data=RAW_DATA,
            ref_set=REF_SET,
            corrector_fn=always_429,
            rate_limit_wait=60.0,
        )

        assert result["status"] == "UNRESOLVED"
        # All attempts should be RATE_LIMITED
        for attempt in result["attempts"]:
            assert attempt["status"] == "RATE_LIMITED"
