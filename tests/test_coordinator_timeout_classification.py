"""Regression: Vol3 timeout maps to failure_mode=timeout for both
wrapper-backed (memory arg_type) and dynamically-registered (vol_generic)
plugin paths.

run_tool does NOT accept arg_type as a kwarg. arg_type is derived from
_TOOL_REGISTRY[tool_name] internally. Tests pick registered tool names:
  - vol_mftscan is registered with arg_type="memory"
  - vol_ldrmodules is registered with arg_type="vol_generic"

run_tool is an instrumentation wrapper over _run_tool_inner. Its outer
except Exception does NOT hijack the timeout classification because
_run_tool_inner catches VolatilityTimeout and returns a dict (not raises).
"""
from unittest.mock import patch

import sift_sentinel.coordinator  # populates _TOOL_REGISTRY (V-gate)
from sift_sentinel.tools.common import VolatilityTimeout


def test_memory_branch_timeout_returns_failure_mode_timeout():
    """vol_mftscan timeout via memory arg_type branch.

    Patches run_volatility at BOTH common and memory_extended2 namespaces
    because memory_extended2 does `from ..common import run_volatility`
    which binds the name at import time in memory_extended2.
    """
    sift_sentinel.coordinator.new_tool_health()

    def fake_run_volatility(tool_name, image_path):
        raise VolatilityTimeout(f"{tool_name} timed out after 90s")

    with patch("sift_sentinel.tools.common.run_volatility", fake_run_volatility), \
         patch("sift_sentinel.tools.memory_extended2.run_volatility", fake_run_volatility):
        result = sift_sentinel.coordinator.run_tool(
            tool_name="vol_mftscan",
            image_path="/fake/mem.img",
            disk_path="",
        )

    assert result["failure_mode"] == "timeout", (
        f"expected failure_mode=timeout, got {result.get('failure_mode')!r}"
    )
    assert "timed out" in result["error"].lower()
    assert result["record_count"] == 0
    assert result["output"] == []


def test_vol_generic_branch_timeout_returns_failure_mode_timeout():
    """vol_ldrmodules timeout via vol_generic arg_type branch."""
    sift_sentinel.coordinator.new_tool_health()

    def fake_run_volatility(tool_name, image_path):
        raise VolatilityTimeout(f"{tool_name} timed out after 300s")

    with patch("sift_sentinel.coordinator.run_volatility", fake_run_volatility):
        result = sift_sentinel.coordinator.run_tool(
            tool_name="vol_ldrmodules",
            image_path="/fake/mem.img",
            disk_path="",
        )

    assert result["failure_mode"] == "timeout"
    assert "timed out" in result["error"].lower()


def test_vol_generic_runtime_error_still_classified_correctly():
    """Non-timeout RuntimeError must still map to runtime_error, not timeout or exception."""
    sift_sentinel.coordinator.new_tool_health()

    def fake_run_volatility(tool_name, image_path):
        raise RuntimeError("parser failed on corrupted output")

    with patch("sift_sentinel.coordinator.run_volatility", fake_run_volatility):
        result = sift_sentinel.coordinator.run_tool(
            tool_name="vol_ldrmodules",
            image_path="/fake/mem.img",
            disk_path="",
        )

    assert result["failure_mode"] == "runtime_error"


def test_volatility_timeout_is_not_runtime_error():
    """Architectural: VolatilityTimeout must NOT be a RuntimeError subclass.

    If this fails, wrappers swallow timeouts via `except RuntimeError`
    and the whole fix is defeated.
    """
    assert not issubclass(VolatilityTimeout, RuntimeError)
    assert issubclass(VolatilityTimeout, Exception)
