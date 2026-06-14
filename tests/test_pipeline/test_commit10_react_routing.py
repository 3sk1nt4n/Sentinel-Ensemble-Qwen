"""Commit 10: ReAct tool-dispatch arg-type routing (N4-routing fix)."""
from pathlib import Path
from unittest.mock import patch

from sift_sentinel.coordinator import (
    DEFAULT_MFT_END,
    DEFAULT_MFT_START,
    step_11_investigate,
)


def _finding(pid: int = 1234, fid: str = "F001") -> dict:
    """Finding shape matching step_11 claim reads: type, pid, process."""
    return {
        "finding_id": fid,
        "claims": [
            {"type": "pid", "pid": pid, "process": "target.exe",
             "source_tools": []},
        ],
    }


def _invoke_picks(tool_name: str, pid: int = 1234):
    """Fake invoke_fn matching step_11 call signature.

    step_11 invokes: invoke_fn(str(prompt_path), 30, 3, lambda: {...})
    step_11 reads: raw.get("action"); for tool action reads raw.get("tool"),
    raw.get("pid"), raw.get("reasoning").
    """
    call_count = {"n": 0}

    def _fn(prompt_path, timeout=30, max_turns=3, fallback_fn=None):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return {
                "action": "tool",
                "tool": tool_name,
                "pid": pid,
                "reasoning": f"investigating with {tool_name}",
            }
        return {
            "action": "conclude",
            "conclusion": "investigation complete",
            "verdict": "confirmed_malicious",
            "severity": "MEDIUM",
            "evidence_summary": "test",
        }
    return _fn


def test_invoke_picks_fake_matches_step11_call_signature():
    """Sanity: fake must accept step_11 positional call pattern."""
    fake = _invoke_picks("vol_handles")
    result = fake("/tmp/fake_prompt.md", 30, 3, lambda: {})
    assert isinstance(result, dict)
    assert result.get("action") in ("tool", "conclude")


def test_step11_signature_has_disk_path_mft_start_mft_end():
    """Commit 10 extends signature with three new kwargs with defaults."""
    import inspect
    sig = inspect.signature(step_11_investigate)
    params = sig.parameters
    assert "disk_path" in params
    assert "mft_start" in params
    assert "mft_end" in params
    assert params["disk_path"].default == ""
    assert params["mft_start"].default == DEFAULT_MFT_START
    assert params["mft_end"].default == DEFAULT_MFT_END


def test_step11_routes_vol_generic_through_filter_tool_by_pid(tmp_path):
    """Vol3 tools must still route through filter_tool_by_pid."""
    with patch(
        "sift_sentinel.coordinator.filter_tool_by_pid",
        return_value=[{"PID": 1234, "Name": "target.exe"}],
    ) as mock_filter, patch(
        "sift_sentinel.coordinator.run_tool",
    ) as mock_run_tool:
        step_11_investigate(
            [_finding()], tmp_path, False, _invoke_picks("vol_handles"),
            image_path="/fake.raw",
        )
        assert mock_filter.called
        assert not mock_run_tool.called


def test_step11_routes_disk_tool_through_run_tool(tmp_path):
    """Disk arg_type tools must go through run_tool, not filter_tool_by_pid."""
    envelope = {"output": [{"program": "notepad.exe"}], "failure_mode": None}
    with patch(
        "sift_sentinel.coordinator.run_tool",
        return_value=envelope,
    ) as mock_run_tool, patch(
        "sift_sentinel.coordinator.filter_tool_by_pid",
    ) as mock_filter:
        step_11_investigate(
            [_finding()], tmp_path, False, _invoke_picks("get_amcache"),
            image_path="/fake.raw",
            disk_path="/fake_disk",
        )
        assert mock_run_tool.called
        assert not mock_filter.called


def test_step11_normalizes_run_tool_envelope_entries_dict(tmp_path):
    """run_tool envelope with dict containing entries must normalize to list."""
    envelope = {
        "output": {"entries": [{"x": 1}, {"x": 2}]},
        "failure_mode": None,
    }
    with patch(
        "sift_sentinel.coordinator.run_tool",
        return_value=envelope,
    ):
        result = step_11_investigate(
            [_finding()], tmp_path, False, _invoke_picks("parse_event_logs"),
            image_path="/fake.raw", disk_path="/fake_disk",
        )
    inv = result["investigations"][0]
    details = inv["details"][0]
    assert details["result_count"] == 2


def test_step11_run_tool_failure_mode_yields_empty_result(tmp_path):
    """Envelope with failure_mode must log warning and return empty list."""
    envelope = {
        "output": [],
        "failure_mode": "parse_error",
        "error": "bad input",
    }
    with patch(
        "sift_sentinel.coordinator.run_tool",
        return_value=envelope,
    ):
        result = step_11_investigate(
            [_finding()], tmp_path, False, _invoke_picks("get_amcache"),
            image_path="/fake.raw", disk_path="/fake_disk",
        )
    details = result["investigations"][0]["details"][0]
    assert details["result_count"] == 0


def test_step11_run_tool_exception_caught_gracefully(tmp_path):
    """Exceptions from run_tool must be caught and produce empty result."""
    with patch(
        "sift_sentinel.coordinator.run_tool",
        side_effect=RuntimeError("boom"),
    ):
        result = step_11_investigate(
            [_finding()], tmp_path, False, _invoke_picks("get_amcache"),
            image_path="/fake.raw", disk_path="/fake_disk",
        )
    details = result["investigations"][0]["details"][0]
    assert details["result_count"] == 0
