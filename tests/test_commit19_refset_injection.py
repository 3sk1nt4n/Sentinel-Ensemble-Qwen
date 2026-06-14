"""Commit 19 invariants: SC prompt reference-set injection.

L19-1: build_sc_prompt accepts ref_set parameter
L19-2: ref_set produces verifiable_references section with real keys
L19-3: ref_set=None preserves backward-compatible behavior
L19-4: run_pipeline corrector_fn passes ref_set AND ref_set is constructed
"""
from __future__ import annotations

import inspect
from pathlib import Path


def test_L19_1_build_sc_prompt_accepts_ref_set():
    """build_sc_prompt signature must accept ref_set parameter."""
    from sift_sentinel.coordinator import build_sc_prompt
    sig = inspect.signature(build_sc_prompt)
    params = set(sig.parameters.keys())
    assert "ref_set" in params, f"build_sc_prompt missing ref_set param. Got: {sorted(params)}"


def test_L19_2_ref_set_produces_verifiable_references(tmp_path):
    """When ref_set provided, prompt must include verifiable_references section
    with keys from pid_to_process, connections, paths (real shape: values may
    be lists or strings, we only inject keys)."""
    from sift_sentinel.coordinator import build_sc_prompt
    # Real ref_set shape: pid_to_process values are LISTS, paths values are LISTS
    ref_set = {
        "pid_to_process": {
            "6784": ["winlogon.exe"],
            "6504": ["taskhostex.exe"],
        },
        "connections": {
            "2340:192.0.2.5:58810->192.0.2.12:135": "Uninstall.exe",
        },
        "paths": {
            "package.mum": ["/Windows/servicing/package.mum"],
        },
    }
    prompt_path = build_sc_prompt(
        {"dummy": []}, "test error", tmp_path, 1, ref_set=ref_set,
    )
    prompt_text = Path(prompt_path).read_text()
    assert "<verifiable_references>" in prompt_text, "Missing verifiable_references section"
    assert "valid_pids" in prompt_text, "Missing valid_pids list"
    assert "valid_connections" in prompt_text, "Missing valid_connections list"
    assert "valid_paths" in prompt_text, "Missing valid_paths list"
    # Verify real keys appear
    assert "6784" in prompt_text, "Valid PID key not injected"
    assert "2340:192.0.2.5:58810" in prompt_text, "Valid connection key not injected"
    assert "package.mum" in prompt_text, "Valid path key not injected"


def test_L19_3_ref_set_none_no_injection(tmp_path):
    """When ref_set is None, no verifiable_references section appears
    (backward-compatible behavior)."""
    from sift_sentinel.coordinator import build_sc_prompt
    prompt_path = build_sc_prompt(
        {"dummy": []}, "test error", tmp_path, 1,
    )
    prompt_text = Path(prompt_path).read_text()
    assert "<verifiable_references>" not in prompt_text, \
        "ref_set=None should not produce verifiable_references section"
    # Core sections still present
    assert "<validator_error>" in prompt_text
    assert "<raw_data>" in prompt_text


def test_L19_4_corrector_fn_passes_ref_set_and_ref_set_constructed():
    """run_pipeline.py must:
    1. Construct ref_set via build_reference_set
    2. corrector_fn must pass ref_set to build_sc_prompt

    Defends against future refactors breaking either the build step or
    the injection point.
    """
    with open("run_pipeline.py") as f:
        content = f.read()
    assert "ref_set = build_reference_set" in content, \
        "run_pipeline.py no longer builds ref_set (should call build_reference_set)"
    assert "ref_set=ref_set" in content, \
        "run_pipeline.py corrector_fn does not pass ref_set to build_sc_prompt"
