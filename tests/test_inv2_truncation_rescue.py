"""TDD: Inv2 truncation resilience.

When the 16384-token output cap is hit mid-JSON, json.loads raises
JSONDecodeError and _live_call returns None -> 0 findings.
rescue_truncated_findings_json must salvage any complete finding objects
from the truncated text so a cap-hit yields real findings rather than zero.

Dataset-agnostic: purely structural JSON token scanning, no domain logic.
"""
import json

from sift_sentinel.tools.json_rescue import rescue_truncated_findings_json as rescue


def test_rescue_extracts_complete_finding_from_truncated_json():
    """One complete object before truncation: must be recovered."""
    truncated = (
        '{"findings": ['
        '{"finding_id": "F001", "title": "Suspicious process", "claims": []},'
        '{"finding_id": "F002", "title": "Incomplete'
    )
    result = rescue(truncated)
    assert result is not None
    assert "findings" in result
    assert len(result["findings"]) >= 1
    assert result["findings"][0]["finding_id"] == "F001"


def test_rescue_extracts_multiple_complete_findings():
    """Two complete objects before truncation: both recovered."""
    f1 = {"finding_id": "F001", "title": "A", "claims": [{"type": "path", "value": "/tmp/x"}]}
    f2 = {"finding_id": "F002", "title": "B", "claims": []}
    truncated = '{"findings": [' + json.dumps(f1) + "," + json.dumps(f2) + ",{incomplete"
    result = rescue(truncated)
    assert result is not None
    assert len(result["findings"]) == 2
    assert result["findings"][1]["finding_id"] == "F002"


def test_rescue_returns_none_when_no_findings_key():
    assert rescue("some random truncated text without findings key") is None


def test_rescue_returns_none_on_empty_findings_array():
    assert rescue('{"findings": [') is None


def test_rescue_returns_none_on_empty_string():
    assert rescue("") is None


def test_rescue_handles_complete_valid_json_as_passthrough():
    """If the JSON is complete and valid, rescue should still return the findings."""
    data = {"findings": [{"finding_id": "F001", "title": "ok", "claims": []}]}
    result = rescue(json.dumps(data))
    assert result is not None
    assert len(result["findings"]) == 1


def test_rescue_tolerates_markdown_fence():
    """Model sometimes wraps JSON in ```json fences; rescue must strip them."""
    truncated = (
        "```json\n"
        '{"findings": [{"finding_id": "F001", "title": "ok", "claims": []},\n'
        '{"finding_id": "F002", "title": "trunc'
    )
    result = rescue(truncated)
    assert result is not None
    assert len(result["findings"]) >= 1
