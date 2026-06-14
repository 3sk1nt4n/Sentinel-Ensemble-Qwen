"""Tests for Step 11 cached result filtering (no Vol re-runs)."""
from __future__ import annotations

from unittest.mock import patch, MagicMock

from sift_sentinel.coordinator import (
    LOW_YIELD_TOOLS,
    _filter_cached_results,
    filter_tool_by_pid,
    step_11_investigate,
)
from pathlib import Path


# ── _filter_cached_results unit tests ────────────────────────────────────


class TestFilterCachedResults:
    def test_filter_cached_by_pid(self):
        """10 records, filter PID 1204, returns 1 match."""
        records = [{"PID": i, "Name": f"proc{i}"} for i in range(10)]
        records.append({"PID": 1204, "Name": "sqlsvc.exe"})
        mandatory = {"vol_netscan": {"output": records, "record_count": 11}}
        result = _filter_cached_results("vol_netscan", 1204, mandatory)
        assert result is not None
        assert len(result) == 1
        assert result[0]["PID"] == 1204

    def test_filter_cached_no_pid_column(self):
        """Amcache records have no PID column -> returns all."""
        records = [{"Path": "\\sqlsvc.exe", "SHA1": "abc"}, {"Path": "\\cmd.exe", "SHA1": "def"}]
        mandatory = {"get_amcache": {"output": records, "record_count": 2}}
        result = _filter_cached_results("get_amcache", 1204, mandatory)
        assert result is not None
        assert len(result) == 2  # all returned, no PID column

    def test_filter_cached_empty(self):
        """Tool not in mandatory_results -> returns None."""
        result = _filter_cached_results("vol_handles", 1204, {})
        assert result is None

    def test_filter_cached_none_pid(self):
        """pid=None -> returns all records without filtering."""
        records = [{"PID": 100, "Name": "a"}, {"PID": 200, "Name": "b"}]
        mandatory = {"vol_psscan": {"output": records, "record_count": 2}}
        result = _filter_cached_results("vol_psscan", None, mandatory)
        assert result is not None
        assert len(result) == 2

    def test_filter_cached_list_envelope(self):
        """Raw list (no envelope dict) -> treated as records."""
        records = [{"PID": 42, "Name": "x"}]
        mandatory = {"vol_psscan": records}
        result = _filter_cached_results("vol_psscan", 42, mandatory)
        assert result is not None
        assert len(result) == 1

    def test_filter_cached_pid_string_coercion(self):
        """PID as string in records matches int filter."""
        records = [{"PID": "1204", "Name": "sqlsvc.exe"}]
        mandatory = {"vol_netscan": {"output": records, "record_count": 1}}
        result = _filter_cached_results("vol_netscan", 1204, mandatory)
        assert result is not None
        assert len(result) == 1

    def test_filter_cached_handles_dict(self):
        """Dict record containers (e.g. amcache) are coerced to list of values,
        not crashed with KeyError: 0 when accessing records[0]."""
        records_dict = {
            "a": {"Path": "\\sqlsvc.exe", "SHA1": "abc"},
            "b": {"Path": "\\cmd.exe", "SHA1": "def"},
            "c": {"Path": "\\foo.exe", "SHA1": "ghi"},
        }
        mandatory = {"get_amcache": {"output": records_dict, "record_count": 3}}
        result = _filter_cached_results("get_amcache", None, mandatory)
        assert result is not None
        assert isinstance(result, list)
        assert len(result) == 3
        paths = {r["Path"] for r in result}
        assert paths == {"\\sqlsvc.exe", "\\cmd.exe", "\\foo.exe"}

    def test_filter_cached_handles_empty_dict(self):
        """Empty dict -> returns None (treated like no records)."""
        mandatory = {"get_amcache": {"output": {}, "record_count": 0}}
        result = _filter_cached_results("get_amcache", None, mandatory)
        assert result is None


# ── step_11_investigate integration tests ────────────────────────────────


class TestInvestigationCached:
    def _make_finding(self, fid="F001", pid=9006, process="sqlsvc.exe"):
        return {
            "finding_id": fid,
            "claims": [{"type": "pid", "pid": pid, "process": process}],
            "source_tools": ["vol_pstree"],
            "confidence_level": "MEDIUM",
        }

    def test_investigation_uses_cached(self, tmp_path):
        """When cached data exists, filter_tool_by_pid is NOT called."""
        mandatory = {
            "vol_netscan": {
                "output": [
                    {"PID": 9006, "ForeignAddr": "192.0.2.129", "State": "ESTABLISHED"},
                    {"PID": 999, "ForeignAddr": "10.0.0.1", "State": "CLOSED"},
                ],
                "record_count": 2,
            },
        }

        call_count = 0

        def fake_invoke(prompt_path, timeout, max_turns, fallback_fn):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {"action": "tool", "tool": "vol_netscan", "pid": 9006,
                        "reasoning": "check connections"}
            return {"action": "conclude", "conclusion": "found C2",
                    "evidence_summary": "netscan confirms"}

        with patch("sift_sentinel.coordinator.filter_tool_by_pid") as mock_live:
            result = step_11_investigate(
                [self._make_finding()], tmp_path, False, fake_invoke,
                mandatory_results=mandatory,
            )
            mock_live.assert_not_called()

        assert len(result["investigations"]) == 1
        inv = result["investigations"][0]
        assert inv["turns"] >= 1
        details = inv["details"][0]
        assert details["result_count"] == 1  # only PID 9006

    def test_investigation_fallback_live(self, tmp_path):
        """Tool NOT in cached mandatory_results -> falls back to live Vol."""
        call_count = 0

        def fake_invoke(prompt_path, timeout, max_turns, fallback_fn):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {"action": "tool", "tool": "vol_handles", "pid": 9006,
                        "reasoning": "check handles"}
            return {"action": "conclude", "conclusion": "done",
                    "evidence_summary": ""}

        with patch("sift_sentinel.coordinator.filter_tool_by_pid",
                   return_value=[{"PID": 9006, "Handle": "0x1234"}]) as mock_live:
            result = step_11_investigate(
                [self._make_finding()], tmp_path, False, fake_invoke,
                mandatory_results={"vol_netscan": {"output": [], "record_count": 0}},
            )
            mock_live.assert_called_once()

        assert len(result["investigations"]) == 1


# ── Cross-finding investigation cache (Optimization 1) ──────────────────


class TestStep11InvestigationCache:
    """filter_tool_by_pid + step_11_investigate must reuse Vol3 output
    across findings rather than rescanning per-finding."""

    def _make_finding(self, fid, pid, process="sqlsvc.exe"):
        return {
            "finding_id": fid,
            "claims": [{"type": "pid", "pid": pid, "process": process}],
            "source_tools": ["vol_pstree"],
            "confidence_level": "MEDIUM",
        }

    # ── Unit: cache stores UNFILTERED records ──────────────────────────

    def test_step11_cache_stores_unfiltered(self):
        """filter_tool_by_pid with cache dict stores ALL records, not the
        PID-A subset. This lets finding-B (different PID) serve from cache."""
        records = [
            {"PID": 9002, "Name": "a"},
            {"PID": 9001, "Name": "b"},
            {"PID": 9999, "Name": "c"},
            {"PID": 9002, "Name": "d"},
        ]
        cache: dict[str, list[dict]] = {}
        with patch(
            "sift_sentinel.coordinator.run_volatility", return_value=records,
        ):
            result = filter_tool_by_pid(
                "vol_handles", 9002, "/fake.raw", cache=cache,
            )
        # Returned value is filtered to PID 9002 (2 records)
        assert len(result) == 2
        assert all(r["PID"] == 9002 for r in result)
        # Cache holds UNFILTERED records (all 4)
        assert "vol_handles" in cache
        assert len(cache["vol_handles"]) == 4
        cached_pids = {r["PID"] for r in cache["vol_handles"]}
        assert cached_pids == {9002, 9001, 9999}

    def test_step11_cache_hit_skips_run_volatility(self):
        """Second call with same tool hits cache -- run_volatility not invoked
        again, even if the PID filter differs."""
        records = [
            {"PID": 9002, "Name": "a"},
            {"PID": 9001, "Name": "b"},
        ]
        cache: dict[str, list[dict]] = {}
        with patch(
            "sift_sentinel.coordinator.run_volatility", return_value=records,
        ) as mock_vol:
            # First call: miss, populates cache
            filter_tool_by_pid("vol_handles", 9002, "/fake.raw", cache=cache)
            assert mock_vol.call_count == 1
            # Second call: different PID, should hit cache
            result = filter_tool_by_pid(
                "vol_handles", 9001, "/fake.raw", cache=cache,
            )
            assert mock_vol.call_count == 1  # no additional call
        assert len(result) == 1
        assert result[0]["PID"] == 9001

    def test_step11_cache_none_disables_caching(self):
        """Backward-compat: cache=None means no cache side effects."""
        records = [{"PID": 100, "Name": "a"}, {"PID": 200, "Name": "b"}]
        with patch(
            "sift_sentinel.coordinator.run_volatility", return_value=records,
        ) as mock_vol:
            filter_tool_by_pid("vol_handles", 100, "/fake.raw")
            filter_tool_by_pid("vol_handles", 200, "/fake.raw")
            assert mock_vol.call_count == 2  # no cache -> re-runs

    # ── Integration: cross-finding reuse ────────────────────────────────

    def test_step11_cache_reuse_different_pid(self, tmp_path):
        """Two findings, same tool (vol_handles), different PIDs.
        run_volatility should be invoked only ONCE -- the second finding
        serves from the cache built by the first."""
        invoke_calls = {"by_finding": {"F001": 0, "F003": 0}}

        def fake_invoke(prompt_path, timeout, max_turns, fallback_fn):
            # Parallel-safe fake: infer the finding/PID from prompt content
            # rather than relying on global worker scheduling order.
            from pathlib import Path as _Path

            prompt_text = _Path(prompt_path).read_text(errors="ignore")

            if "F003" in prompt_text or "9001" in prompt_text:
                finding_id, pid = "F003", 9001
            else:
                finding_id, pid = "F001", 9002

            invoke_calls["by_finding"][finding_id] += 1

            if invoke_calls["by_finding"][finding_id] == 1:
                return {
                    "action": "tool",
                    "tool": "vol_handles",
                    "pid": pid,
                    "reasoning": f"{finding_id} handles",
                }

            return {
                "action": "conclude",
                "conclusion": f"{finding_id} done",
                "evidence_summary": "",
            }

        records = [
            {"PID": 9002, "Name": "h1"},
            {"PID": 9001, "Name": "h2"},
            {"PID": 9999, "Name": "h3"},
        ]
        findings = [
            self._make_finding("F001", 9002),
            self._make_finding("F003", 9001),
        ]
        with patch(
            "sift_sentinel.coordinator.run_volatility", return_value=records,
        ) as mock_vol:
            result = step_11_investigate(
                findings, tmp_path, False, fake_invoke, image_path="/fake.raw",
            )
            # One Vol3 scan total across both findings
            assert mock_vol.call_count == 1

        # Each finding got its own PID-filtered subset
        inv_by_id = {i["finding_id"]: i for i in result["investigations"]}
        f001_sample = inv_by_id["F001"]["details"][0]["result_sample"]
        f003_sample = inv_by_id["F003"]["details"][0]["result_sample"]
        assert all(r["PID"] == 9002 for r in f001_sample)
        assert all(r["PID"] == 9001 for r in f003_sample)

    def test_step11_cache_reset_between_runs(self, tmp_path):
        """Two separate step_11_investigate invocations must NOT share
        cache state -- each run scans once."""
        def fake_invoke(prompt_path, timeout, max_turns, fallback_fn):
            # Always: request vol_handles, then conclude
            if "turn0" in str(prompt_path):
                return {"action": "tool", "tool": "vol_handles",
                        "pid": 9002, "reasoning": "r"}
            return {"action": "conclude", "conclusion": "done",
                    "evidence_summary": ""}

        records = [{"PID": 9002, "Name": "a"}]
        findings = [self._make_finding("F001", 9002)]

        with patch(
            "sift_sentinel.coordinator.run_volatility", return_value=records,
        ) as mock_vol:
            step_11_investigate(
                findings, tmp_path, False, fake_invoke, image_path="/fake.raw",
            )
            step_11_investigate(
                findings, tmp_path, False, fake_invoke, image_path="/fake.raw",
            )
            # Second run gets its own cache -> another Vol3 scan
            assert mock_vol.call_count == 2

    def test_step11_cache_defers_to_mandatory(self, tmp_path):
        """Precedence: mandatory_results wins over the Step 11 cache.
        If Step 6 already cached a tool globally, Step 11 must serve from
        that (no Vol3, no Step 11 cache duplication). This protects against
        double-storage and keeps provenance unambiguous."""
        # mandatory_results has vol_netscan for PID 9002 -> should be used.
        mandatory = {
            "vol_netscan": {
                "output": [
                    {"PID": 9002, "ForeignAddr": "192.0.2.129",
                     "State": "ESTABLISHED"},
                    {"PID": 999, "ForeignAddr": "10.0.0.1", "State": "CLOSED"},
                ],
                "record_count": 2,
            },
        }

        def fake_invoke(prompt_path, timeout, max_turns, fallback_fn):
            if "turn0" in str(prompt_path):
                return {"action": "tool", "tool": "vol_netscan",
                        "pid": 9002, "reasoning": "connections"}
            return {"action": "conclude", "conclusion": "c2 confirmed",
                    "evidence_summary": ""}

        with patch(
            "sift_sentinel.coordinator.run_volatility",
        ) as mock_vol, patch(
            "sift_sentinel.coordinator.filter_tool_by_pid",
        ) as mock_live:
            result = step_11_investigate(
                [self._make_finding("F001", 9002)], tmp_path, False,
                fake_invoke, image_path="/fake.raw",
                mandatory_results=mandatory,
            )
            # Neither Vol3 nor the live/cache fallback path should run --
            # the mandatory cache satisfied the request first.
            mock_vol.assert_not_called()
            mock_live.assert_not_called()

        detail = result["investigations"][0]["details"][0]
        assert detail["result_count"] == 1  # PID 9002 only
        assert detail["result_sample"][0]["PID"] == 9002


# ── Evidence-speaks low-yield policy ─────────────────────────────────


class TestStep11NoLowYieldSkipPolicy:
    """The system must not skip tools using prior observed-yield sheets."""

    def test_low_yield_registry_is_empty(self):
        assert LOW_YIELD_TOOLS == {}
