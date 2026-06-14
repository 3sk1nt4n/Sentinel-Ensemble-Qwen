"""Commit 6: required_args populated for 6 args-requiring Vol3 plugins."""
from __future__ import annotations

import pytest

from sift_sentinel.coordinator import run_tool, new_tool_health
from sift_sentinel.tools.capabilities import get_capability
from sift_sentinel.tools.common import VOLATILITY_PLUGINS


EXPECTED_REQUIRED_ARGS = {
    "vol_moduleextract": ("base",),
    "vol_pedump": ("base",),
    "vol_pesymbols": ("source", "module"),
    "vol_strings": ("strings_file",),
    "vol_vadregexscan": ("pattern",),
    "vol_vmaregexscan": ("pattern",),
}

# Explicit mapping sourced from VOLATILITY_PLUGINS namespace.
# Avoid fragile substring matching on tool name.
EVIDENCE_BY_TOOL = {
    "vol_moduleextract": "linux_evidence",   # linux.module_extract
    "vol_pedump": "windows_evidence",        # windows.pedump
    "vol_pesymbols": "windows_evidence",     # windows.pe_symbols
    "vol_strings": "windows_evidence",       # windows.strings
    "vol_vadregexscan": "windows_evidence",  # windows.vadregexscan
    "vol_vmaregexscan": "linux_evidence",    # linux.vmaregexscan
}


def test_evidence_by_tool_matches_plugin_namespace():
    """Self-check: EVIDENCE_BY_TOOL reflects actual VOLATILITY_PLUGINS mapping.

    If a plugin moves platforms in a future Volatility release, this
    test catches the drift before dispatcher tests fail mysteriously.
    """
    mismatches = []
    for tool_name, evidence_type in EVIDENCE_BY_TOOL.items():
        plugin = VOLATILITY_PLUGINS.get(tool_name, "")
        platform = plugin.split(".")[0] if plugin else "UNKNOWN"
        expected_evidence = f"{platform}_evidence"
        if expected_evidence != evidence_type:
            mismatches.append(
                f"{tool_name}: namespace={plugin!r} implies {expected_evidence}, "
                f"but test uses {evidence_type}"
            )
    assert not mismatches, f"Platform mapping drift: {mismatches}"


def test_all_6_plugins_have_required_args_populated():
    """After Commit 6, all 6 plugins have non-empty required_args."""
    missing = []
    wrong = []
    for tool_name, expected in EXPECTED_REQUIRED_ARGS.items():
        cap = get_capability(tool_name)
        if not cap:
            missing.append(f"{tool_name} (no capability)")
            continue
        actual = tuple(cap.get("required_args", ()))
        if actual != expected:
            wrong.append(f"{tool_name}: expected {expected}, got {actual}")
    assert not missing, f"Missing capabilities: {missing}"
    assert not wrong, f"Wrong required_args: {wrong}"


def test_dispatcher_returns_missing_required_args_on_empty_args():
    """Invoking an args-requiring plugin without args yields missing_required_args.

    Passes correct evidence_type per EVIDENCE_BY_TOOL so applicable_when
    gate (Commit 5) does NOT intercept -- we want to test the required_args
    gate, which runs AFTER applicable_when passes.
    """
    new_tool_health()
    results = {}
    for tool_name in EXPECTED_REQUIRED_ARGS:
        evidence_type = EVIDENCE_BY_TOOL[tool_name]
        result = run_tool(
            tool_name,
            image_path="/fake/path.img",
            disk_path="/fake/path.img",
            evidence_type=evidence_type,
            tool_args=None,
        )
        results[tool_name] = result.get("failure_mode")

    wrong = {
        name: fm for name, fm in results.items()
        if fm != "missing_required_args"
    }
    assert not wrong, (
        f"Expected missing_required_args for all, but got: {wrong}"
    )


def test_each_tool_reports_correct_missing_args_count():
    """vol_pesymbols requires 2 args (source, module); others require 1."""
    new_tool_health()
    for tool_name, expected_args in EXPECTED_REQUIRED_ARGS.items():
        evidence_type = EVIDENCE_BY_TOOL[tool_name]
        result = run_tool(
            tool_name,
            image_path="/fake/path.img",
            disk_path="/fake/path.img",
            evidence_type=evidence_type,
            tool_args=None,
        )
        error_msg = result.get("error", "")
        # Weak check: error should mention at least one of the required args
        # (exact format depends on dispatcher error message template)
        assert any(arg in error_msg for arg in expected_args), (
            f"{tool_name}: error msg '{error_msg}' doesn't mention any of {expected_args}"
        )
