"""Tests for tool failure awareness -- Claude reasons about failures autonomously."""

from __future__ import annotations

from sift_sentinel.coordinator import (
    collect_tool_failures,
    build_inv2_prompt,
    _build_inv3_oneshot_prompt,
)


# ── Fixtures ─────────────────────────────────────────────────────────────

GOOD_OUTPUTS = {
    "vol_pstree": {
        "output": [{"PID": 4, "ImageFileName": "System"}],
        "record_count": 1,
    },
    "vol_netscan": {
        "output": [{"PID": 4, "LocalAddr": "0.0.0.0", "LocalPort": 445}],
        "record_count": 1,
    },
}

OUTPUTS_WITH_FAILURES = {
    "vol_pstree": {
        "output": [],
        "record_count": 0,
        "error": "vol_pstree timed out after 120s",
    },
    "vol_netscan": {
        "output": [{"PID": 4, "LocalAddr": "0.0.0.0", "LocalPort": 445}],
        "record_count": 1,
    },
    "vol_malfind": {
        "output": [],
        "record_count": 0,
    },
    "get_amcache": {
        "error": "FileNotFoundError: amcache hive not found",
        "tool_name": "get_amcache",
    },
}


# ── Test 1: Only explicit errors are failures, not empty results ─────────

def test_collect_tool_failures():
    """Only explicit 'error' key produces failure entries.
    Empty results (e.g. malfind with no injections) are NOT failures."""
    failures = collect_tool_failures(OUTPUTS_WITH_FAILURES)
    tools = {f["tool"] for f in failures}
    assert "vol_pstree" in tools      # has explicit error key
    assert "get_amcache" in tools      # has explicit error key
    assert "vol_netscan" not in tools  # has data, no error
    assert "vol_malfind" not in tools  # empty but no error = legitimate
    assert len(failures) == 2
    by_tool = {f["tool"]: f for f in failures}
    assert by_tool["vol_pstree"]["status"] == "error"
    assert by_tool["get_amcache"]["status"] == "error"


# ── Test 2: Failures injected into Inv2 prompt ──────────────────────────

def test_tool_failures_passed_to_inv2(tmp_path):
    """When failures exist, Inv2 prompt includes <tool_failures> block."""
    failures = collect_tool_failures(OUTPUTS_WITH_FAILURES)
    prompt_path = build_inv2_prompt(
        OUTPUTS_WITH_FAILURES, 50000, tmp_path, tool_failures=failures,
    )
    prompt_text = prompt_path.read_text()
    assert "<tool_failures>" in prompt_text
    assert "vol_pstree" in prompt_text
    assert "get_amcache" in prompt_text
    assert "FAILURE HANDLING INSTRUCTIONS" in prompt_text
    assert "vol_psscan" in prompt_text  # alternative suggestion


# ── Test 3: Failures injected into Inv3 prompt ──────────────────────────

def test_tool_failures_passed_to_inv3(tmp_path):
    """When failures exist, Inv3 investigation prompt includes failure block."""
    failures = collect_tool_failures(OUTPUTS_WITH_FAILURES)
    findings = [{"finding_id": "F001", "artifact": "test.exe", "claims": []}]
    prompt_path = _build_inv3_oneshot_prompt(
        findings, tmp_path, tool_failures=failures,
    )
    prompt_text = prompt_path.read_text()
    assert "<tool_failures>" in prompt_text
    assert "vol_pstree" in prompt_text
    assert "FAILURE HANDLING INSTRUCTIONS" in prompt_text


# ── Test 4: No failures, no block ───────────────────────────────────────

def test_no_failures_no_block(tmp_path):
    """When all tools succeed, no failure block in either prompt."""
    failures = collect_tool_failures(GOOD_OUTPUTS)
    assert failures == []

    prompt_path = build_inv2_prompt(
        GOOD_OUTPUTS, 50000, tmp_path, tool_failures=failures,
    )
    assert "<tool_failures>" not in prompt_path.read_text()

    findings = [{"finding_id": "F001", "artifact": "test.exe", "claims": []}]
    inv3_path = _build_inv3_oneshot_prompt(
        findings, tmp_path, tool_failures=failures,
    )
    assert "<tool_failures>" not in inv3_path.read_text()


# ── Test 5: Dry-run sample data produces no failures ────────────────────

def test_dry_run_no_failures():
    """Dry-run sample data (non-empty outputs) produces zero failures."""
    sample_outputs = {
        "vol_pstree": {"output": [{"PID": 4}], "record_count": 1},
        "vol_malfind": {"output": [{"PID": 100}], "record_count": 1},
        "get_amcache": {"output": [{"sha1": "abc"}], "record_count": 1},
    }
    assert collect_tool_failures(sample_outputs) == []
