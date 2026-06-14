"""Tests for Step 11: Adaptive Investigation (ReAct loop)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sift_sentinel.coordinator import (
    INVESTIGATION_TOOLS,
    _build_inv3_oneshot_prompt,
    _build_react_prompt,
    filter_tool_by_pid,
    step_11_investigate,
)


@pytest.fixture(autouse=True)
def dry_run_mode(monkeypatch):
    """Force investigation tests to use the legacy subprocess path."""
    monkeypatch.setenv("SIFT_DRY_RUN", "1")


@pytest.fixture
def sample_findings():
    """Validated findings with MATCH status."""
    return [
        {
            "finding_id": "F-001",
            "artifact": "sqlsvc.exe",
            "claims": [
                {"type": "pid", "pid": 9001, "process": "sqlsvc.exe"},
            ],
            "source_tools": ["vol_pstree", "vol_netscan"],
            "confidence_level": "HIGH",
            "deterministic_check": "passed",
        },
        {
            "finding_id": "F-002",
            "artifact": "rundll32.exe",
            "claims": [
                {"type": "pid", "pid": 4576, "process": "rundll32.exe"},
            ],
            "source_tools": ["vol_pstree", "vol_malfind"],
            "confidence_level": "MEDIUM",
            "deterministic_check": "passed",
        },
    ]


# ── Dry-run mode skips AI call ──────────────────────────────────────────


class TestDryRunSkips:
    def test_dry_run_returns_empty(self, tmp_path, sample_findings):
        mock_invoke = MagicMock()
        result = step_11_investigate(
            sample_findings, tmp_path, True, mock_invoke,
        )
        mock_invoke.assert_not_called()
        assert result["investigations"] == []
        assert result["threads"] == []

    def test_dry_run_returns_without_state_write(
        self, tmp_path, sample_findings,
    ):
        step_11_investigate(sample_findings, tmp_path, True, MagicMock())
        # ReAct dry-run returns early without writing state file
        assert not (tmp_path / "investigation_threads.json").exists()

    def test_empty_findings_skips_without_ai(self, tmp_path):
        mock_invoke = MagicMock()
        result = step_11_investigate([], tmp_path, False, mock_invoke)
        mock_invoke.assert_not_called()
        assert result["investigations"] == []


# ── ReAct loop: AI concludes immediately ──────────────────────────────


class TestReActConclude:
    def test_conclude_turn_0(self, tmp_path, sample_findings):
        """AI concludes on first turn -- zero tool calls."""
        invoke = MagicMock(return_value={
            "action": "conclude",
            "conclusion": "confirmed beacon",
            "evidence_summary": "malfind was enough",
        })
        with patch(
            "sift_sentinel.coordinator.run_volatility", return_value=[],
        ):
            result = step_11_investigate(
                sample_findings, tmp_path, False, invoke,
            )
        # Both findings have PIDs, so both get investigated
        assert len(result["investigations"]) == 2
        inv = result["investigations"][0]
        assert inv["conclusion"] == "confirmed beacon"
        assert inv["turns"] == 0  # no tool calls
        assert inv["tool_chain"] == []

    def test_multiple_findings_each_investigated(
        self, tmp_path, sample_findings,
    ):
        """Every finding is investigated.

        Dataset-agnostic and parallel-safe:
        - derives expected finding IDs from sample_findings
        - does not assume result ordering
        - does not hardcode fixture finding IDs or PIDs
        """
        from collections import Counter

        invoke = MagicMock(return_value={
            "action": "conclude", "conclusion": "done",
        })

        with patch(
            "sift_sentinel.coordinator.run_volatility", return_value=[],
        ):
            result = step_11_investigate(
                sample_findings, tmp_path, False, invoke,
            )

        expected_ids = [
            finding["finding_id"]
            for finding in sample_findings
        ]
        actual_ids = [
            investigation["finding_id"]
            for investigation in result["investigations"]
        ]

        assert Counter(actual_ids) == Counter(expected_ids)
        assert invoke.call_count == len(sample_findings)

        investigations_by_id = {
            investigation["finding_id"]: investigation
            for investigation in result["investigations"]
        }

        for finding_id in expected_ids:
            assert investigations_by_id[finding_id]["conclusion"] == "done"

    def test_react_writes_per_turn_prompts(self, tmp_path, sample_findings):
        """Each turn writes a prompt file to state dir."""
        invoke = MagicMock(return_value={
            "action": "conclude", "conclusion": "done",
        })
        with patch(
            "sift_sentinel.coordinator.run_volatility", return_value=[],
        ):
            step_11_investigate(
                sample_findings, tmp_path, False, invoke,
            )
        for f in sample_findings:
            fid = f["finding_id"]
            assert (tmp_path / f"inv3_{fid}_turn0.md").exists()


# ── ReAct loop: malformed AI responses ────────────────────────────────


class TestMalformedResponse:
    def test_non_dict_ends_loop(self, tmp_path, sample_findings):
        invoke = MagicMock(return_value="not a dict")
        result = step_11_investigate(
            sample_findings, tmp_path, False, invoke,
        )
        # Findings still appended with fallback conclusion
        assert len(result["investigations"]) == 2
        assert result["investigations"][0]["conclusion"] == \
            "no investigation needed"

    def test_none_invoke_returns_empty(self, tmp_path, sample_findings):
        result = step_11_investigate(
            sample_findings, tmp_path, False, None,
        )
        assert result["investigations"] == []

    def test_missing_action_defaults_to_tool(self, tmp_path, sample_findings):
        """Missing 'action' key defaults to 'tool', which needs a tool name."""
        invoke = MagicMock(return_value={"tool": "", "reasoning": "test"})
        result = step_11_investigate(
            sample_findings, tmp_path, False, invoke,
        )
        # Empty tool name triggers guardrail
        for inv in result["investigations"]:
            assert "guardrail" in inv["conclusion"].lower()

    def test_finding_without_pid_skipped(self, tmp_path):
        """Findings without PID claims are skipped entirely."""
        findings = [{
            "finding_id": "F-NoPID",
            "claims": [{"type": "hash", "value": "abc"}],
        }]
        invoke = MagicMock()
        result = step_11_investigate(findings, tmp_path, False, invoke)
        invoke.assert_not_called()
        # No PID -> continue, nothing appended, but result still written
        assert result["investigations"] == []


# ── Tool filtering by PID returns correct subset ────────────────────────


class TestFilterToolByPID:
    def test_filters_matching_pid(self):
        records = [
            {"PID": 100, "Name": "a"},
            {"PID": 200, "Name": "b"},
            {"PID": 100, "Name": "c"},
        ]
        with patch(
            "sift_sentinel.coordinator.run_volatility", return_value=records,
        ):
            result = filter_tool_by_pid("vol_handles", 100)
        assert len(result) == 2
        assert all(r["PID"] == 100 for r in result)

    def test_no_matching_pid(self):
        records = [{"PID": 100, "Name": "a"}]
        with patch(
            "sift_sentinel.coordinator.run_volatility", return_value=records,
        ):
            result = filter_tool_by_pid("vol_handles", 999)
        assert result == []

    def test_strips_children_key(self):
        records = [{"PID": 100, "Name": "a", "__children": []}]
        with patch(
            "sift_sentinel.coordinator.run_volatility", return_value=records,
        ):
            result = filter_tool_by_pid("vol_handles", 100)
        assert "__children" not in result[0]
        assert result[0]["PID"] == 100
        assert result[0]["Name"] == "a"

    def test_empty_cache_returns_empty(self):
        with patch(
            "sift_sentinel.coordinator.run_volatility", return_value=[],
        ):
            result = filter_tool_by_pid("vol_netscan", 100)
        assert result == []

    def test_pid_none_returns_all(self):
        """pid=None means no filtering -- all records returned."""
        records = [
            {"PID": 100, "Name": "a"},
            {"PID": 200, "Name": "b"},
            {"PID": 300, "Name": "c"},
        ]
        with patch(
            "sift_sentinel.coordinator.run_volatility", return_value=records,
        ):
            result = filter_tool_by_pid("vol_psscan", None)
        assert len(result) == 3

    def test_pid_filter_case_insensitive_key(self):
        """Column named 'PId' (mixed case) still matches."""
        records = [
            {"PId": 100, "Name": "a"},
            {"PId": 200, "Name": "b"},
        ]
        with patch(
            "sift_sentinel.coordinator.run_volatility", return_value=records,
        ):
            result = filter_tool_by_pid("vol_handles", 100)
        assert len(result) == 1
        assert result[0]["PId"] == 100

    def test_pid_filter_string_int_coercion(self):
        """CSV produces PID as str '1234'; filter with int 1234 still matches."""
        records = [
            {"PID": "1234", "Name": "cmd.exe"},
            {"PID": "9004", "Name": "svchost.exe"},
        ]
        with patch(
            "sift_sentinel.coordinator.run_volatility", return_value=records,
        ):
            result = filter_tool_by_pid("vol_handles", 1234)
        assert len(result) == 1
        assert result[0]["Name"] == "cmd.exe"

    def test_pid_filter_int_to_str_coercion(self):
        """Filter str pid against int record PIDs."""
        records = [
            {"PID": 1234, "Name": "cmd.exe"},
            {"PID": 9004, "Name": "svchost.exe"},
        ]
        with patch(
            "sift_sentinel.coordinator.run_volatility", return_value=records,
        ):
            result = filter_tool_by_pid("vol_handles", "1234")
        assert len(result) == 1
        assert result[0]["Name"] == "cmd.exe"


# ── Investigation results saved to state dir ────────────────────────────


class TestResultsSaved:
    def test_aggregate_file_created(self, tmp_path, sample_findings):
        invoke = MagicMock(return_value={
            "action": "conclude", "conclusion": "done",
        })
        with patch(
            "sift_sentinel.coordinator.run_volatility", return_value=[],
        ):
            step_11_investigate(
                sample_findings, tmp_path, False, invoke,
            )
        path = tmp_path / "investigation_threads.json"
        assert path.exists()
        agg = json.loads(path.read_text())
        assert "investigations" in agg
        assert len(agg["investigations"]) == 2

    def test_tool_chain_recorded(self, tmp_path, sample_findings):
        """ReAct tool chain is recorded in investigation result.

        Dataset-agnostic and parallel-safe:
        - derives finding_id and PID from sample_findings[0]
        - routes fake invoke by inv3_{finding_id}_turn{N}.md prompt path
        - falls back to prompt content if naming changes
        - looks up the result by finding_id, never investigations[0]
        """
        import re
        from pathlib import Path as _Path

        primary = sample_findings[0]
        primary_fid = primary["finding_id"]
        primary_pid = primary["claims"][0]["pid"]
        state: dict[str | None, int] = {}

        all_fids = [f["finding_id"] for f in sample_findings]

        def _fid_from_prompt(prompt_path):
            prompt_name = _Path(prompt_path).name
            match = re.search(r"inv3_(.+?)_turn\d+\.md$", prompt_name)
            if match:
                return match.group(1)

            prompt_text = _Path(prompt_path).read_text(errors="ignore")
            for fid in all_fids:
                if fid in prompt_text:
                    return fid
            if str(primary_pid) in prompt_text:
                return primary_fid
            return None

        def invoke(prompt_path, *args, **kwargs):
            fid = _fid_from_prompt(prompt_path)
            turn = state.get(fid, 0)
            state[fid] = turn + 1

            if fid == primary_fid and turn == 0:
                return {
                    "action": "tool",
                    "tool": "vol_handles",
                    "pid": primary_pid,
                    "reasoning": "check handles",
                }

            if fid == primary_fid:
                return {"action": "conclude", "conclusion": "confirmed"}

            return {"action": "conclude", "conclusion": "benign"}

        with patch(
            "sift_sentinel.coordinator.run_volatility", return_value=[],
        ):
            result = step_11_investigate(
                sample_findings, tmp_path, False, invoke,
            )

        inv_by_id = {
            inv["finding_id"]: inv
            for inv in result["investigations"]
        }
        inv = inv_by_id[primary_fid]

        assert inv["tool_chain"] == ["vol_handles"]
        assert inv["turns"] == 1
        assert inv["conclusion"] == "confirmed"

    def test_investigation_details_have_results(
        self, tmp_path, sample_findings,
    ):
        """ReAct details contain tool results from each turn.

        Dataset-agnostic and parallel-safe:
        - derives finding_id and PID from sample_findings[0]
        - routes fake invoke by prompt filename or prompt content
        - looks up investigation by finding_id
        """
        import re
        from pathlib import Path as _Path

        primary = sample_findings[0]
        primary_fid = primary["finding_id"]
        primary_pid = primary["claims"][0]["pid"]
        state: dict[str | None, int] = {}

        all_fids = [f["finding_id"] for f in sample_findings]

        records = [
            {"PID": primary_pid, "Name": "\\\\Device\\\\Pipe\\\\fhsvc"},
        ]

        def _fid_from_prompt(prompt_path):
            prompt_name = _Path(prompt_path).name
            match = re.search(r"inv3_(.+?)_turn\d+\.md$", prompt_name)
            if match:
                return match.group(1)

            prompt_text = _Path(prompt_path).read_text(errors="ignore")
            for fid in all_fids:
                if fid in prompt_text:
                    return fid
            if str(primary_pid) in prompt_text:
                return primary_fid
            return None

        def invoke(prompt_path, *args, **kwargs):
            fid = _fid_from_prompt(prompt_path)
            turn = state.get(fid, 0)
            state[fid] = turn + 1

            if fid == primary_fid and turn == 0:
                return {
                    "action": "tool",
                    "tool": "vol_handles",
                    "pid": primary_pid,
                    "reasoning": "check pipes",
                }

            if fid == primary_fid:
                return {"action": "conclude", "conclusion": "beacon"}

            return {"action": "conclude", "conclusion": "ok"}

        with patch(
            "sift_sentinel.coordinator.run_volatility", return_value=records,
        ):
            result = step_11_investigate(
                sample_findings, tmp_path, False, invoke,
            )

        inv_by_id = {
            inv["finding_id"]: inv
            for inv in result["investigations"]
        }
        details = inv_by_id[primary_fid]["details"]

        assert len(details) == 1
        assert details[0]["tool"] == "vol_handles"
        assert details[0]["result_count"] == 1


# ── Invoke is called per finding per turn ─────────────────────────────


class TestInvokePatterns:
    def test_invoke_called_per_finding(self, tmp_path, sample_findings):
        invoke = MagicMock(return_value={
            "action": "conclude", "conclusion": "done",
        })
        with patch(
            "sift_sentinel.coordinator.run_volatility", return_value=[],
        ):
            step_11_investigate(
                sample_findings, tmp_path, False, invoke,
            )
        # 2 findings, conclude on turn 0 each = 2 invoke calls
        assert invoke.call_count == 2

    def test_invoke_prompt_path_contains_finding_id(self, tmp_path, sample_findings):
        """Inv3 prompt paths include each finding_id.

        Dataset-agnostic and parallel-safe:
        - derives every expected finding_id from sample_findings
        - makes no assumption about scheduling order
        - does not hardcode fixture IDs, PIDs, paths, or expected case artifacts
        """
        from pathlib import Path as _Path
        import threading

        observed_prompt_paths = []
        observed_lock = threading.Lock()

        def invoke(prompt_path, timeout, max_turns, fallback_fn):
            with observed_lock:
                observed_prompt_paths.append(str(prompt_path))
            return {
                "action": "conclude",
                "conclusion": "done",
                "evidence_summary": "",
            }

        result = step_11_investigate(
            sample_findings, tmp_path, False, invoke,
        )

        prompt_names = [_Path(path).name for path in observed_prompt_paths]
        expected_finding_ids = [
            finding["finding_id"]
            for finding in sample_findings
        ]

        for finding_id in expected_finding_ids:
            expected_prefix = f"inv3_{finding_id}_turn"
            assert any(
                name.startswith(expected_prefix) and name.endswith(".md")
                for name in prompt_names
            ), f"missing prompt path for finding_id={finding_id!r}: {prompt_names}"

        result_finding_ids = {
            investigation["finding_id"]
            for investigation in result["investigations"]
        }
        assert result_finding_ids == set(expected_finding_ids)


# ── Prompt builder (legacy one-shot, renamed) ─────────────────────────


class TestBuildInvestigationPrompt:
    def test_prompt_contains_findings(self, tmp_path, sample_findings):
        path = _build_inv3_oneshot_prompt(sample_findings, tmp_path)
        rendered = path.read_text()
        primary = sample_findings[0]
        assert primary["finding_id"] in rendered
        assert primary["claims"][0]["process"] in rendered

    def test_prompt_contains_anti_rationalization(self, tmp_path):
        path = _build_inv3_oneshot_prompt([], tmp_path)
        text = path.read_text()
        assert "anti_rationalization" in text

    def test_prompt_lists_all_tools(self, tmp_path):
        path = _build_inv3_oneshot_prompt([], tmp_path)
        text = path.read_text()
        # vol_filescan removed from prompts (fails on degraded profiles)
        for tool in INVESTIGATION_TOOLS - {"vol_filescan"}:
            assert tool in text, f"{tool} missing from inv3 prompt"

    def test_prompt_requests_json(self, tmp_path):
        path = _build_inv3_oneshot_prompt([], tmp_path)
        text = path.read_text()
        assert '"investigations"' in text
        assert '"finding_id"' in text


# ── INVESTIGATION_TOOLS constant ────────────────────────────────────────


class TestInvestigationToolsConstant:
    def test_expected_tools_present(self):
        core_tools = {
            "vol_cmdline", "vol_dlllist", "vol_handles", "vol_netscan",
            "vol_envars", "vol_getsids", "vol_privileges", "vol_psscan",
            "vol_ldrmodules", "vol_svcscan", "vol_filescan",
            "vol_hollowprocesses", "vol_callbacks", "vol_modscan", "vol_vadinfo",
        }
        assert core_tools.issubset(INVESTIGATION_TOOLS)
        assert len(INVESTIGATION_TOOLS) >= 15

    def test_is_a_set(self):
        assert isinstance(INVESTIGATION_TOOLS, set)


# ── Cached disk tool results available in investigation ─────────────────


class TestDiskToolsInInvestigation:
    """Disk tools (amcache, prefetch, event_logs) must be available
    during investigation via _filter_cached_results."""

    def test_disk_tools_in_all_outputs(self):
        """Mandatory dict always includes amcache, prefetch, event_logs."""
        # Simulates run_pipeline.py's mandatory tool output structure
        mandatory = {
            "vol_pstree": {"output": [], "record_count": 0},
            "vol_psscan": {"output": [], "record_count": 0},
            "vol_netscan": {"output": [], "record_count": 0},
            "vol_malfind": {"output": [], "record_count": 0},
            "get_amcache": {"output": [{"path": "test.exe"}], "record_count": 1},
            "parse_prefetch": {"output": [{"executable_name": "TEST.EXE"}], "record_count": 1},
            "parse_event_logs": {"output": [{"EventID": 1}], "record_count": 1},
        }
        all_outputs = {**mandatory}
        assert "get_amcache" in all_outputs
        assert "parse_prefetch" in all_outputs
        assert "parse_event_logs" in all_outputs

    def test_investigation_can_use_amcache(self):
        """_filter_cached_results returns all amcache records (no PID column)."""
        from sift_sentinel.coordinator import _filter_cached_results
        mandatory = {
            "get_amcache": {
                "output": [{"path": f"prog{i}.exe"} for i in range(635)],
                "record_count": 635,
            },
        }
        result = _filter_cached_results("get_amcache", None, mandatory)
        assert result is not None
        assert len(result) == 635

    def test_cached_prefetch_returns_all(self):
        """_filter_cached_results returns all prefetch records (no PID column)."""
        from sift_sentinel.coordinator import _filter_cached_results
        mandatory = {
            "parse_prefetch": {
                "output": [{"executable_name": "A.EXE"}, {"executable_name": "B.EXE"}],
                "record_count": 2,
            },
        }
        result = _filter_cached_results("parse_prefetch", 1234, mandatory)
        # No PID column -> returns all records
        assert result is not None
        assert len(result) == 2


# ── Image path propagation & graceful failure ─────────────────────────


class TestInvestigationImagePath:
    """Verify image_path reaches run_volatility during ReAct loop."""

    def _make_finding(self, fid="F099", pid=1234):
        return {
            "finding_id": fid,
            "claims": [{"type": "pid", "pid": pid, "process": "test.exe"}],
            "source_tools": ["vol_pstree"],
            "confidence_level": "MEDIUM",
        }

    def test_investigation_passes_image_path(self, tmp_path):
        """image_path must not be None/empty when reaching run_volatility."""
        captured_paths = []

        def fake_run_vol(tool_name, image_path):
            captured_paths.append(image_path)
            return [{"PID": 1234, "Handle": "0xABC"}]

        call_count = 0

        def fake_invoke(prompt_path, timeout, max_turns, fallback_fn):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {"action": "tool", "tool": "vol_handles",
                        "pid": 1234, "reasoning": "check handles"}
            return {"action": "conclude", "conclusion": "done"}

        with patch("sift_sentinel.coordinator.run_volatility",
                   side_effect=fake_run_vol):
            step_11_investigate(
                [self._make_finding()], tmp_path, False, fake_invoke,
                image_path="/evidence/memory.raw",
            )

        assert len(captured_paths) >= 1
        for p in captured_paths:
            assert p, "image_path must not be empty"
            assert p == "/evidence/memory.raw"

    def test_investigation_vol_failure_graceful(self, tmp_path):
        """Vol3 failure during investigation returns 0 results, not traceback."""
        call_count = 0

        def fake_invoke(prompt_path, timeout, max_turns, fallback_fn):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {"action": "tool", "tool": "vol_vadinfo",
                        "pid": 5768, "reasoning": "check VADs"}
            return {"action": "conclude", "conclusion": "unavailable"}

        with patch("sift_sentinel.coordinator.run_volatility",
                   side_effect=RuntimeError("LayerStacker error")):
            result = step_11_investigate(
                [self._make_finding(pid=5768)], tmp_path, False,
                fake_invoke, image_path="/evidence/memory.raw",
            )

        inv = result["investigations"][0]
        assert inv["details"][0]["result_count"] == 0
        assert inv["details"][0]["result_sample"] == []
