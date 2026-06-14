"""Slot 31E-DB.5.6 -- tool-health wording never conflates N/A and fail.

Dataset-agnostic. No API key, no live run, no network. Forbidden
phrases are assembled by concatenation so this file is not itself a
static forbidden-token list.
"""

from __future__ import annotations

from sift_sentinel.validation.report_gates import (
    format_tool_health_summary,
)


def test_tool_health_wording_not_applicable_is_not_failure():
    s = format_tool_health_summary(
        selected=20, data_producing=19, not_applicable=1, failed=0)

    assert "Tools selected: 20" in s
    assert "Data-producing tools: 19" in s
    assert "Not applicable: 1" in s
    assert "Failed: 0" in s

    # Must NOT imply a partial failure.
    bad_succeeded = " ".join(["19/20", "succeeded"])
    bad_failed_one = " ".join(["Failed:", "1"])
    bad_attempt = " ".join(["19", "of", "20", "attempts", "failed"])
    assert bad_succeeded not in s
    assert bad_failed_one not in s
    assert bad_attempt not in s

    # N/A is explicitly explained as not-a-failure.
    assert "not a failure" in s.lower()


def test_zero_failures_render_cleanly():
    s = format_tool_health_summary(7, 7, 0, 0)
    assert "Tools selected: 7" in s
    assert "Failed: 0" in s


def test_real_failure_is_still_visible():
    s = format_tool_health_summary(10, 7, 1, 2)
    assert "Failed: 2" in s
    assert "Not applicable: 1" in s
