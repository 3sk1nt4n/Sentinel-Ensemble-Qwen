"""MALFIND/timing: run-level memoization of run_volatility.

A Volatility plugin is deterministic for a given (tool, image): the same
(tool, image_path) re-run -- e.g. ReAct re-invoking vol_malfind per PID --
must return the cached result instead of re-executing the ~30s plugin + CSV
retry. Universal (idempotent tool call), safe (identical result, no detection
change). Errors are NOT cached (retryable). Kill-switch SIFT_TOOL_MEMO=0.
"""
from __future__ import annotations

import pytest

import sift_sentinel.tools.common as common


@pytest.fixture(autouse=True)
def _isolate_cache(monkeypatch):
    common.clear_tool_result_cache()
    yield
    common.clear_tool_result_cache()


def _patch_impl(monkeypatch, counter, result=None, raises=None):
    def fake(tool_name, image_path):
        counter.append((tool_name, image_path))
        if raises is not None:
            raise raises
        return list(result if result is not None else [{"pid": 1}])
    monkeypatch.setattr(common, "_run_volatility_impl", fake)


def test_second_identical_call_is_cached(monkeypatch):
    monkeypatch.delenv("SIFT_TOOL_MEMO", raising=False)
    calls = []
    _patch_impl(monkeypatch, calls, result=[{"pid": 4384}])
    a = common.run_volatility("vol_malfind", "/img.mem")
    b = common.run_volatility("vol_malfind", "/img.mem")
    assert a == b == [{"pid": 4384}]
    assert len(calls) == 1                      # executed once, served twice


def test_empty_result_is_also_cached(monkeypatch):
    # the live regression: malfind returns 0 records and re-runs pay the CSV
    # retry each time -- the empty list must be memoized too
    monkeypatch.delenv("SIFT_TOOL_MEMO", raising=False)
    calls = []
    _patch_impl(monkeypatch, calls, result=[])
    assert common.run_volatility("vol_malfind", "/img.mem") == []
    assert common.run_volatility("vol_malfind", "/img.mem") == []
    assert len(calls) == 1


def test_different_image_reexecutes(monkeypatch):
    monkeypatch.delenv("SIFT_TOOL_MEMO", raising=False)
    calls = []
    _patch_impl(monkeypatch, calls, result=[{"pid": 1}])
    common.run_volatility("vol_malfind", "/a.mem")
    common.run_volatility("vol_malfind", "/b.mem")
    assert len(calls) == 2


def test_different_tool_reexecutes(monkeypatch):
    monkeypatch.delenv("SIFT_TOOL_MEMO", raising=False)
    calls = []
    _patch_impl(monkeypatch, calls, result=[{"pid": 1}])
    common.run_volatility("vol_malfind", "/a.mem")
    common.run_volatility("vol_psscan", "/a.mem")
    assert len(calls) == 2


def test_kill_switch_off_reexecutes(monkeypatch):
    monkeypatch.setenv("SIFT_TOOL_MEMO", "0")
    calls = []
    _patch_impl(monkeypatch, calls, result=[{"pid": 1}])
    common.run_volatility("vol_malfind", "/img.mem")
    common.run_volatility("vol_malfind", "/img.mem")
    assert len(calls) == 2


def test_errors_are_not_cached(monkeypatch):
    # a timeout / failure must stay retryable -- never memoized as a result
    monkeypatch.delenv("SIFT_TOOL_MEMO", raising=False)
    calls = []
    _patch_impl(monkeypatch, calls, raises=RuntimeError("boom"))
    with pytest.raises(RuntimeError):
        common.run_volatility("vol_malfind", "/img.mem")
    with pytest.raises(RuntimeError):
        common.run_volatility("vol_malfind", "/img.mem")
    assert len(calls) == 2


def test_cached_list_is_isolated_copy(monkeypatch):
    # a caller mutating the returned list must not corrupt the cache
    monkeypatch.delenv("SIFT_TOOL_MEMO", raising=False)
    calls = []
    _patch_impl(monkeypatch, calls, result=[{"pid": 1}])
    a = common.run_volatility("vol_malfind", "/img.mem")
    a.append({"pid": 999})
    b = common.run_volatility("vol_malfind", "/img.mem")
    assert b == [{"pid": 1}]
