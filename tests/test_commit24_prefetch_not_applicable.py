"""Commit 24: parse_prefetch not_applicable status + N/A display row.

Property tests. All inputs synthetic (tmp directories). No dataset
fingerprints. Tests assert:
  - not_applicable status returned when Prefetch dir absent
  - no "error" key in not_applicable return (collect_tool_failures exclusion)
  - reason field includes policy-constant Windows Server context
  - structural keys preserved (output, record_count)
  - collect_tool_failures integration: not_applicable excluded
  - run_pipeline.py display loop has N/A branch with correct cascade order
  - not_applicable return shape complete with all expected keys
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from sift_sentinel.tools.disk_extended import parse_prefetch
from sift_sentinel.coordinator import collect_tool_failures


def test_L24_1_returns_not_applicable_when_dir_absent(tmp_path):
    """Property: parse_prefetch returns status=not_applicable
    when Prefetch directory does not exist."""
    result = parse_prefetch(disk_mount=str(tmp_path))
    assert result.get("status") == "not_applicable"
    assert result.get("record_count") == 0
    assert result.get("output") == []


def test_L24_2_no_error_key_in_not_applicable_return(tmp_path):
    """Regression guard: not_applicable return must NOT have 'error'
    key, so collect_tool_failures correctly excludes it from failures
    list. This is the bug being fixed."""
    result = parse_prefetch(disk_mount=str(tmp_path))
    assert "error" not in result, (
        f"not_applicable return must not have 'error' key to avoid "
        f"misclassification as tool failure. Got: {result}"
    )


def test_L24_3_reason_contains_policy_constant():
    """Property: reason text is a policy constant about Windows Server,
    not a dataset-specific value."""
    with tempfile.TemporaryDirectory() as tmp:
        result = parse_prefetch(disk_mount=tmp)
        reason = result.get("reason", "")
        assert "Windows Server" in reason
        assert "disabled by default" in reason


def test_L24_4_structural_keys_preserved(tmp_path):
    """Property: output and record_count keys still present in
    not_applicable return (consistency with successful return shape)."""
    result = parse_prefetch(disk_mount=str(tmp_path))
    assert "output" in result
    assert "record_count" in result
    assert isinstance(result["output"], list)
    assert isinstance(result["record_count"], int)


def test_L24_5_collect_tool_failures_excludes_not_applicable(tmp_path):
    """Integration: when parse_prefetch returns not_applicable,
    collect_tool_failures does NOT list it in failures.

    Shape-agnostic: checks both 'tool' and 'tool_name' keys since
    coordinator.py failure dicts use varying key names across call
    sites (lines 1125, 1175, 1301 use 'tool_name', collect_tool_failures
    uses 'tool'). This test asserts parse_prefetch is absent regardless
    of which key is used."""
    prefetch_result = parse_prefetch(disk_mount=str(tmp_path))
    outputs = {"parse_prefetch": prefetch_result}
    failures = collect_tool_failures(outputs)
    failure_tools = [
        f.get("tool") or f.get("tool_name") for f in failures
    ]
    assert "parse_prefetch" not in failure_tools, (
        f"parse_prefetch with not_applicable status should NOT appear "
        f"in failures list. Got: {failures}"
    )


def test_L24_6_display_loop_has_not_applicable_branch():
    """Structural: run_pipeline.py display loop contains the N/A branch
    for status == 'not_applicable', positioned BEFORE the err branch
    and before EMPTY branch in the cascade.

    Uses full-cascade ordering assertion: finds position of each expected
    branch string and asserts they appear in order. More robust than
    .find(s, start_idx) which always returns >= start_idx."""
    content = Path("run_pipeline.py").read_text()
    assert 'Commit 24: check for not_applicable status' in content
    assert 'status = all_outputs.get(t, {}).get("status")' in content
    # Cascade ordering: N/A -> err -> EMPTY
    expected_order = (
        'if status == "not_applicable":',
        'elif err:',
        'elif cnt == 0:',
    )
    positions = [content.find(s) for s in expected_order]
    assert all(p >= 0 for p in positions), (
        f"Display cascade branch missing. Positions: {positions}"
    )
    assert positions == sorted(positions), (
        f"Display cascade branches out of order. Expected N/A -> err -> "
        f"EMPTY, got positions: {positions}"
    )


def test_L24_7_not_applicable_return_shape_complete():
    """Property: not_applicable return has all expected keys and types."""
    with tempfile.TemporaryDirectory() as tmp:
        result = parse_prefetch(disk_mount=tmp)
        assert set(["output", "record_count", "status", "reason"]).issubset(result.keys())
        assert isinstance(result["status"], str)
        assert isinstance(result["reason"], str)
        assert result["status"] == "not_applicable"
