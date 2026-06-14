"""
Tests for common helpers: run_volatility, prepare_prompt,
strip_markdown_fences, run_tools_parallel.
"""

import os
import json
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from sift_sentinel.tools.common import (
    VOLATILITY_PLUGINS,
    VolatilityTimeout,
    _flatten_vol_tree,
    _parse_vol_csv,
    prepare_prompt,
    run_tools_parallel,
    run_volatility,
    strip_markdown_fences,
)


# ── run_volatility ──────────────────────────────────────────────────────


class TestRunVolatility:
    def test_no_plugin_mapping_raises(self):
        with pytest.raises(ValueError, match="No Volatility plugin"):
            run_volatility("vol_nonexistent", "/evidence/test.img")

    @patch("sift_sentinel.tools.common.subprocess.run")
    def test_success_returns_parsed_json(self, mock_subproc):
        records = [{"PID": 4, "ImageFileName": "System"}]
        mock_subproc.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(records),
            stderr="",
        )
        result = run_volatility("vol_pstree", "/evidence/test.img")
        assert result == records

    @patch("sift_sentinel.tools.common.subprocess.run")
    def test_nonzero_returncode_raises(self, mock_subproc):
        mock_subproc.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="Error: unsupported",
        )
        with pytest.raises(RuntimeError, match="vol_pstree.*unavailable"):
            run_volatility("vol_pstree", "/evidence/test.img")

    @patch("sift_sentinel.tools.common.subprocess.run")
    def test_timeout_raises(self, mock_subproc):
        import subprocess as sp
        mock_subproc.side_effect = sp.TimeoutExpired(cmd="vol", timeout=120)
        with pytest.raises(VolatilityTimeout, match="timed out"):
            run_volatility("vol_pstree", "/evidence/test.img")

    @patch("sift_sentinel.tools.common.subprocess.run")
    def test_bad_json_raises(self, mock_subproc):
        mock_subproc.return_value = MagicMock(
            returncode=0,
            stdout="not json at all",
            stderr="",
        )
        with pytest.raises(RuntimeError, match="not parseable"):
            run_volatility("vol_pstree", "/evidence/test.img")

    @patch("sift_sentinel.tools.common.subprocess.run")
    def test_image_path_passed_to_subprocess(self, mock_subproc):
        mock_subproc.return_value = MagicMock(
            returncode=0, stdout="[]", stderr="",
        )
        run_volatility("vol_pstree", "/my/evidence.img")
        cmd = mock_subproc.call_args[0][0]
        assert "-f" in cmd
        assert "/my/evidence.img" in cmd

    def test_all_plugins_mapped(self):
        # Floor is the hardcoded fallback size; dynamic discovery via
        # `vol --help` can only grow the map, never shrink it.
        from sift_sentinel.tools.common import _VOL_CANONICAL_ALIASES
        assert len(VOLATILITY_PLUGINS) >= len(_VOL_CANONICAL_ALIASES) >= 21
        assert "vol_pstree" in VOLATILITY_PLUGINS
        assert "vol_ssdt" in VOLATILITY_PLUGINS
        assert "vol_ldrmodules" in VOLATILITY_PLUGINS
        for key in VOLATILITY_PLUGINS:
            assert key.startswith("vol_")


# ── _parse_vol_csv ────────────────────────────────────────────────────


class TestParseVolCsv:
    def test_basic(self):
        raw = "PID,PPID,ImageFileName\n4,0,System\n312,4,smss.exe\n"
        result = _parse_vol_csv(raw)
        assert len(result) == 2
        assert result[0] == {"PID": "4", "PPID": "0", "ImageFileName": "System"}
        assert result[1]["ImageFileName"] == "smss.exe"

    def test_quoted_commas(self):
        raw = 'PID,Args\n100,"a,b,c"\n200,"d"\n'
        result = _parse_vol_csv(raw)
        assert len(result) == 2
        assert result[0]["Args"] == "a,b,c"

    def test_framework_header_skipped(self):
        raw = (
            "Volatility 3 Framework 2.20.0\n"
            "PID,PPID\n4,0\n312,4\n"
        )
        result = _parse_vol_csv(raw)
        assert len(result) == 2
        assert result[0]["PID"] == "4"

    def test_empty_returns_empty(self):
        assert _parse_vol_csv("") == []
        assert _parse_vol_csv("   \n\n  ") == []

    def test_generic_headers_no_pid(self):
        """CSV with non-PID headers (e.g. custom plugin) parses correctly."""
        raw = "Alpha,Beta,Gamma\n1,2,3\n4,5,6\n"
        result = _parse_vol_csv(raw)
        assert len(result) == 2
        assert result[0] == {"Alpha": "1", "Beta": "2", "Gamma": "3"}
        assert result[1]["Gamma"] == "6"

    def test_ssdt_style_output(self):
        """SSDT-like CSV output (no PID/PPID columns) returns records."""
        raw = (
            "Volatility 3 Framework 2.20.0\n"
            "Progress:  50.00\n"
            "Index,Address,Module,Symbol,Status\n"
            "0,0xfffff800,ntoskrnl,NtCreateFile,clean\n"
            "1,0xfffff801,ntoskrnl,NtOpenProcess,clean\n"
        )
        result = _parse_vol_csv(raw)
        assert len(result) == 2
        assert result[0]["Module"] == "ntoskrnl"
        assert result[1]["Symbol"] == "NtOpenProcess"
        assert result[0]["Index"] == "0"


class TestFlattenVolTree:
    def test_flattens_children(self):
        tree = [{"PID": 4, "ImageFileName": "System", "__children": [
            {"PID": 388, "ImageFileName": "smss.exe", "__children": [
                {"PID": 624, "ImageFileName": "smss.exe", "__children": []},
            ]},
        ]}]
        flat = _flatten_vol_tree(tree)
        assert len(flat) == 3
        assert flat[0]["PID"] == 4
        assert flat[0]["TreeDepth"] == 0
        assert flat[1]["PID"] == 388
        assert flat[1]["TreeDepth"] == 1
        assert flat[2]["PID"] == 624
        assert flat[2]["TreeDepth"] == 2
        # __children must not be in flattened output
        for rec in flat:
            assert "__children" not in rec

    def test_no_children_passthrough(self):
        records = [{"PID": 4}, {"PID": 100}]
        flat = _flatten_vol_tree(records)
        assert len(flat) == 2
        assert flat[0]["PID"] == 4

    def test_empty(self):
        assert _flatten_vol_tree([]) == []


class TestRunVolatilityTreeFlatten:
    @patch("sift_sentinel.tools.common.subprocess.run")
    def test_json_tree_flattened(self, mock_subproc):
        """JSON returns nested tree -> flattened automatically."""
        tree = [{"PID": 4, "ImageFileName": "System", "__children": [
            {"PID": 388, "ImageFileName": "smss.exe", "__children": []},
            {"PID": 100, "ImageFileName": "foo.exe", "__children": []},
        ]}]
        mock_subproc.return_value = MagicMock(
            returncode=0, stdout=json.dumps(tree), stderr="",
        )
        result = run_volatility("vol_pstree", "/evidence/test.img")
        assert len(result) == 3
        assert result[0]["PID"] == 4
        assert result[1]["PID"] == 388
        # Only one subprocess call (no CSV fallback needed)
        assert mock_subproc.call_count == 1


class TestRunVolatilityCsvFallback:
    @patch("sift_sentinel.tools.common.subprocess.run")
    def test_json_empty_falls_back_to_csv(self, mock_subproc):
        """JSON returns [], CSV returns data -> use CSV data."""
        csv_output = "PID,PPID,ImageFileName\n4,0,System\n312,4,smss.exe\n"
        mock_subproc.side_effect = [
            # First call: JSON returns []
            MagicMock(returncode=0, stdout="[]", stderr=""),
            # Second call: CSV returns data
            MagicMock(returncode=0, stdout=csv_output, stderr=""),
        ]
        result = run_volatility("vol_pstree", "/evidence/test.img")
        assert len(result) == 2
        assert result[0]["PID"] == "4"
        # Verify two subprocess calls: json then csv
        assert mock_subproc.call_count == 2
        first_cmd = mock_subproc.call_args_list[0][0][0]
        second_cmd = mock_subproc.call_args_list[1][0][0]
        assert "json" in first_cmd
        assert "csv" in second_cmd


# ── strip_markdown_fences ──────────────────────────────────────────────

class TestStripMarkdownFences:
    def test_removes_json_fence(self):
        raw = '```json\n{"key": "value"}\n```'
        assert strip_markdown_fences(raw) == '{"key": "value"}'

    def test_removes_plain_fence(self):
        raw = '```\n{"key": "value"}\n```'
        assert strip_markdown_fences(raw) == '{"key": "value"}'

    def test_passthrough_raw_json(self):
        raw = '{"key": "value"}'
        assert strip_markdown_fences(raw) == '{"key": "value"}'

    def test_passthrough_json_array(self):
        raw = '[{"a": 1}]'
        assert strip_markdown_fences(raw) == '[{"a": 1}]'

    def test_handles_whitespace_around_fences(self):
        raw = '  ```json\n{"key": "value"}\n```  '
        assert strip_markdown_fences(raw) == '{"key": "value"}'

    def test_handles_empty_string(self):
        assert strip_markdown_fences("") == ""

    def test_handles_text_before_fence(self):
        """Claude sometimes prefixes with 'Here is the JSON:' before the fence."""
        raw = 'Here is the result:\n```json\n{"key": "value"}\n```'
        result = strip_markdown_fences(raw)
        assert result == '{"key": "value"}'

    def test_result_parses_as_json(self):
        raw = '```json\n{"findings": [{"id": "F-001"}]}\n```'
        result = strip_markdown_fences(raw)
        parsed = json.loads(result)
        assert parsed["findings"][0]["id"] == "F-001"

    def test_preserves_multiline_json(self):
        inner = '{\n  "key": "value",\n  "list": [1, 2, 3]\n}'
        raw = f"```json\n{inner}\n```"
        assert strip_markdown_fences(raw) == inner

    def test_multi_fence_uses_last_block(self):
        """Two fenced blocks: must extract the LAST one (the real JSON)."""
        raw = (
            'Here is an example:\n'
            '```json\n{"example": true}\n```\n\n'
            'And here is the actual result:\n'
            '```json\n{"selected_tools": ["vol_cmdline"]}\n```'
        )
        result = strip_markdown_fences(raw)
        parsed = json.loads(result)
        assert parsed == {"selected_tools": ["vol_cmdline"]}

    def test_multi_fence_first_block_ignored(self):
        """With two blocks, first block content must NOT appear in output."""
        raw = (
            '```json\n{"wrong": true}\n```\n'
            '```json\n{"right": true}\n```'
        )
        result = strip_markdown_fences(raw)
        assert '"wrong"' not in result
        assert json.loads(result) == {"right": True}


# ── prepare_prompt ─────────────────────────────────────────────────────

def _estimate_tokens(text: str) -> int:
    """Rough token estimate: ~4 chars per token."""
    return len(text) // 4


def _make_fake_outputs(sizes: dict[str, int]) -> dict[str, dict]:
    """Create fake tool outputs of approximate token sizes.
    sizes: {tool_name: approx_token_count}"""
    outputs = {}
    for name, tokens in sizes.items():
        char_count = tokens * 4
        outputs[name] = {
            "tool_name": name,
            "execution_time_ms": 100,
            "evidence_path": "/evidence/test.img",
            "record_count": tokens // 10,
            "output": [{"data": "x" * (char_count - 200)}],
        }
    return outputs


class TestPreparePrompt:
    def test_under_budget_passthrough(self):
        """Small outputs that fit within budget should all be included."""
        outputs = _make_fake_outputs({
            "vol_pstree": 500,
            "vol_cmdline": 300,
            "vol_malfind": 200,
        })
        result = prepare_prompt(outputs, token_budget=5000)
        for name in outputs:
            assert name in result

    def test_over_budget_trimmed(self):
        """100K+ tokens of input must be trimmed to fit budget."""
        outputs = _make_fake_outputs({
            "vol_pstree": 27000,
            "vol_netscan": 9000,
            "vol_dlllist": 540000,
            "vol_handles": 3500000,
            "vol_malfind": 1200,
            "vol_cmdline": 4600,
        })
        budget = 30000
        result = prepare_prompt(outputs, token_budget=budget)
        result_tokens = _estimate_tokens(result)
        assert result_tokens <= budget, (
            f"Result {result_tokens} tokens exceeds budget {budget}"
        )

    def test_high_priority_tools_included(self):
        """Critical tools (pstree, malfind, cmdline, netscan) should survive trimming."""
        outputs = _make_fake_outputs({
            "vol_pstree": 5000,
            "vol_malfind": 1200,
            "vol_cmdline": 4600,
            "vol_netscan": 9000,
            "vol_dlllist": 540000,
            "vol_handles": 3500000,
        })
        result = prepare_prompt(outputs, token_budget=30000)
        assert "vol_pstree" in result
        assert "vol_malfind" in result
        assert "vol_cmdline" in result

    def test_returns_string(self):
        outputs = _make_fake_outputs({"vol_malfind": 500})
        result = prepare_prompt(outputs, token_budget=5000)
        assert isinstance(result, str)

    def test_empty_outputs(self):
        result = prepare_prompt({}, token_budget=5000)
        assert isinstance(result, str)

    def test_real_tool_outputs_under_budget(self, monkeypatch):
        """Load tool outputs via mocked run_volatility and verify budget."""
        monkeypatch.setenv("SIFT_DRY_RUN", "1")
        from sift_sentinel.tools.memory import (
            vol_pstree, vol_netscan, vol_malfind, vol_cmdline, vol_dlllist,
        )
        from sift_sentinel.tools.disk import get_amcache

        image = "/evidence/synthetic-memory.img"
        disk = "/evidence/synthetic-disk.e01"
        outputs = {
            "vol_pstree": vol_pstree(image),
            "vol_netscan": vol_netscan(image),
            "vol_malfind": vol_malfind(image),
            "vol_cmdline": vol_cmdline(image),
            "vol_dlllist": vol_dlllist(image),
            "get_amcache": get_amcache(disk),
        }
        budget = 30000
        result = prepare_prompt(outputs, token_budget=budget)
        result_tokens = _estimate_tokens(result)
        assert result_tokens <= budget, (
            f"Real data: {result_tokens} tokens exceeds budget {budget}"
        )


# ── run_tools_parallel ─────────────────────────────────────────────────

def _slow_tool(name: str, delay: float = 0.1) -> dict:
    """Simulates an I/O-bound tool call."""
    time.sleep(delay)
    return {"tool_name": name, "output": f"{name}_result"}


class TestRunToolsParallel:
    def test_returns_all_results(self):
        """All tool results must be returned keyed by name."""
        tasks = {
            "tool_a": (_slow_tool, ("tool_a", 0.01)),
            "tool_b": (_slow_tool, ("tool_b", 0.01)),
            "tool_c": (_slow_tool, ("tool_c", 0.01)),
        }
        results = run_tools_parallel(tasks)
        assert set(results.keys()) == {"tool_a", "tool_b", "tool_c"}
        for name, result in results.items():
            assert result["tool_name"] == name

    def test_parallel_faster_than_sequential(self):
        """5 tools at 0.1s each: sequential=0.5s, parallel<0.3s."""
        tasks = {
            f"tool_{i}": (_slow_tool, (f"tool_{i}", 0.1))
            for i in range(5)
        }
        start = time.monotonic()
        results = run_tools_parallel(tasks)
        elapsed = time.monotonic() - start
        assert len(results) == 5
        assert elapsed < 0.3, f"Parallel took {elapsed:.2f}s, expected <0.3s"

    def test_captures_exceptions(self):
        """A failing tool should not crash the whole batch."""
        def _failing_tool(name):
            raise RuntimeError(f"{name} failed")

        tasks = {
            "good": (_slow_tool, ("good", 0.01)),
            "bad": (_failing_tool, ("bad",)),
        }
        results = run_tools_parallel(tasks)
        assert "good" in results
        assert results["good"]["tool_name"] == "good"
        assert "bad" in results
        assert "error" in results["bad"]

    def test_empty_tasks(self):
        results = run_tools_parallel({})
        assert results == {}
