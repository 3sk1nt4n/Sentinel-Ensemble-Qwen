"""Slot 31D-STEP6-TIMEOUT-CORE-V5 regression tests.

Pins:
  - heavy Vol3 tools (vol_handles, vol_malfind, vol_filescan) get a
    generous, env-tunable timeout (>= 180s);
  - explicit MCP execution-timeout text becomes a degraded timeout
    envelope -- no wasted C29 retry;
  - the Step6 classifier treats that envelope as timeout, never as
    success / not_applicable / benign;
  - Step6 worker resolution is core-aware and lives in one place
    (coordinator.step6_max_workers); run_pipeline.py uses it.
"""

from __future__ import annotations

import ast
import os
import types
from pathlib import Path

import pytest

import sift_sentinel.coordinator as coord
from sift_sentinel import mcp_client
from sift_sentinel.tools import common


# ---------------------------------------------------------------------------
# Helpers: read run_pipeline.py without executing its argparse main.
# ---------------------------------------------------------------------------


_REPO_ROOT = Path(__file__).resolve().parents[2]
_RUN_PIPELINE = _REPO_ROOT / "run_pipeline.py"


def _run_pipeline_source() -> str:
    return _RUN_PIPELINE.read_text(encoding="utf-8")


def _load_run_pipeline_function(name: str):
    """Extract a single top-level function out of run_pipeline.py.

    run_pipeline.py runs argparse at import time, which crashes under
    pytest argv. The established pattern in this repo (see
    tests/test_gemini_token_cap.py) is to compile a single FunctionDef
    node in an isolated module namespace.
    """
    tree = ast.parse(_run_pipeline_source())
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            mod = types.ModuleType(f"_rp_helper_{name}")
            exec(
                compile(
                    ast.Module(body=[node], type_ignores=[]),
                    f"<{name}>",
                    "exec",
                ),
                mod.__dict__,
            )
            return getattr(mod, name)
    raise AssertionError(f"{name} not found in run_pipeline.py")


# ---------------------------------------------------------------------------
# 1) Effective Vol3 timeouts -- heavy plugins get a generous ceiling.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tool_name",
    ["vol_handles", "vol_malfind", "vol_filescan", "vol_psxview"],
)
def test_heavy_vol_tools_have_generous_effective_timeout(tool_name):
    dflt = getattr(common, "VOL_TIMEOUT_DEFAULT", 0)
    timeouts = getattr(common, "VOL_TIMEOUTS", {}) or {}
    effective = int(timeouts.get(tool_name, dflt) or 0)
    assert effective >= 180, (
        f"{tool_name} effective timeout {effective}s < 180s; heavy Vol3 "
        "plugins must get a generous ceiling so they complete once."
    )


@pytest.mark.parametrize(
    "tool_name",
    ["vol_handles", "vol_malfind", "vol_filescan", "vol_psxview"],
)
def test_heavy_vol_tools_use_heavy_timeout_path(tool_name):
    heavy = getattr(common, "VOL_TIMEOUT_HEAVY", None)
    timeouts = getattr(common, "VOL_TIMEOUTS", {}) or {}
    assert isinstance(heavy, int) and heavy > 0
    assert tool_name in timeouts, (
        f"{tool_name} missing from VOL_TIMEOUTS; heavy Vol3 plugins must "
        "explicitly use VOL_TIMEOUT_HEAVY (not the default ceiling)."
    )
    assert timeouts[tool_name] == heavy, (
        f"{tool_name} maps to {timeouts[tool_name]}s, not VOL_TIMEOUT_HEAVY "
        f"({heavy}s); heavy Vol3 plugins must share one tunable ceiling."
    )


def test_vol_timeout_heavy_is_env_tunable():
    val = getattr(common, "VOL_TIMEOUT_HEAVY", None)
    assert isinstance(val, int) and val > 0


# ---------------------------------------------------------------------------
# 2) Explicit-timeout text classifier.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "Error executing tool tool_vol_handles: vol_handles timed out after 90s",
        "vol_malfind timed out after 150s",
        "tool_vol_filescan timed out after 240s",
    ],
)
def test_explicit_timeout_text_is_detected(raw):
    assert mcp_client._sift_mcp_explicit_timeout_text(raw) is True


@pytest.mark.parametrize(
    "raw",
    [
        "timeout budget configured",
        '{"output": [], "record_count": 0}',
        "",
        "Tool ran fine and returned data.",
    ],
)
def test_non_timeout_text_is_ignored(raw):
    assert mcp_client._sift_mcp_explicit_timeout_text(raw) is False


# ---------------------------------------------------------------------------
# 3) Degraded timeout envelope shape.
# ---------------------------------------------------------------------------


def test_timeout_envelope_shape():
    env = mcp_client._sift_mcp_build_timeout_envelope(
        "vol_handles", "vol_handles timed out after 90s",
    )
    assert env["tool_name"] == "vol_handles"
    assert env["output"] == []
    assert env["record_count"] == 0
    assert env["failure_mode"] == "timeout"
    assert env["degraded"] is True
    assert env["retry_attempted"] is False


# ---------------------------------------------------------------------------
# 4) Timeout envelope is treated as failure, not as clean.
# ---------------------------------------------------------------------------


def test_timeout_envelope_classified_as_timeout():
    classify = _load_run_pipeline_function("classify_step6_tool_result")
    env = mcp_client._sift_mcp_build_timeout_envelope(
        "vol_malfind", "vol_malfind timed out after 150s",
    )
    status = classify(env)
    assert status == "timeout"
    assert status not in {"success", "not_applicable"}
    # Defensive: zero records on a timeout must not look benign.
    assert env["record_count"] == 0
    assert env["degraded"] is True


def test_timeout_envelope_is_not_clean_or_not_applicable():
    classify = _load_run_pipeline_function("classify_step6_tool_result")
    env = mcp_client._sift_mcp_build_timeout_envelope(
        "vol_filescan", "tool_vol_filescan timed out after 240s",
    )
    status = classify(env)
    assert status != "success"
    assert status != "not_applicable"


# ---------------------------------------------------------------------------
# 5) Core-aware worker resolution.
# ---------------------------------------------------------------------------


def _core_default() -> int:
    return max(1, min(int(os.cpu_count() or 1), 16))


def test_default_is_core_aware(monkeypatch):
    monkeypatch.delenv("SIFT_STEP6_MAX_WORKERS", raising=False)
    assert coord.step6_max_workers() == _core_default()


def test_env_override_lower_bound(monkeypatch):
    monkeypatch.setenv("SIFT_STEP6_MAX_WORKERS", "1")
    assert coord.step6_max_workers() == 1


def test_env_override_upper_bound(monkeypatch):
    monkeypatch.setenv("SIFT_STEP6_MAX_WORKERS", "16")
    assert coord.step6_max_workers() == 16


def test_env_override_out_of_range_falls_back(monkeypatch):
    monkeypatch.setenv("SIFT_STEP6_MAX_WORKERS", "999")
    assert coord.step6_max_workers() == _core_default()


def test_env_override_invalid_falls_back(monkeypatch):
    monkeypatch.setenv("SIFT_STEP6_MAX_WORKERS", "bad")
    assert coord.step6_max_workers() == _core_default()


def test_env_override_zero_falls_back(monkeypatch):
    monkeypatch.setenv("SIFT_STEP6_MAX_WORKERS", "0")
    assert coord.step6_max_workers() == _core_default()


# ---------------------------------------------------------------------------
# 6) run_pipeline.py shape: no literal-10 fallback, helper imported.
# ---------------------------------------------------------------------------


def test_run_pipeline_drops_literal_10_step6_artifacts():
    src = _run_pipeline_source()
    forbidden = [
        "STEP6_WORKERS_10_GATE",
        "falling back to 10",
        'env.get("SIFT_STEP6_MAX_WORKERS", "10")',
        "requested = 10",
    ]
    for needle in forbidden:
        assert needle not in src, (
            f"run_pipeline.py still contains forbidden artifact: {needle!r}"
        )


def test_run_pipeline_uses_step6_max_workers():
    src = _run_pipeline_source()
    assert "step6_max_workers()" in src, (
        "run_pipeline.py must resolve Step6 workers via "
        "coordinator.step6_max_workers()."
    )


# ---------------------------------------------------------------------------
# 7) No case literals introduced by these patches.
# ---------------------------------------------------------------------------


_PATCHED_FILES = (
    "src/sift_sentinel/tools/common.py",
    "src/sift_sentinel/mcp_client.py",
    "src/sift_sentinel/coordinator.py",
    "run_pipeline.py",
)

# Narrow guard for this rung: the patches deal with timeouts and worker
# counts only, so the obvious failure mode is an case-key term or a
# notorious case-evidence binary name slipping in. audit/nocheat.py runs
# the canonical integrity sweep separately.
_CASE_LITERAL_NEEDLES = (
    "evil.exe",
    "malware.exe",
    "answer_key",
    "answerkey",
    "case-key",
    "answersheet",
    "ANSWERKEY",
)


def _file_text(relpath: str) -> str:
    return (_REPO_ROOT / relpath).read_text(encoding="utf-8")


def test_no_case_literals_in_patched_files():
    for relpath in _PATCHED_FILES:
        text = _file_text(relpath)
        for needle in _CASE_LITERAL_NEEDLES:
            assert needle not in text, (
                f"{relpath} contains forbidden case literal: {needle!r}"
            )
