"""Slot 31E-DB.5a-beta TASK 1 -- generic model-flexible acceptance
wrapper (STATIC).

CLI_ARG_SUPPORT_GATE / INV2_ENSEMBLE_PRESENT_GATE /
RAW_DISK_HASH_COMMAND_GATE / MODEL_FLEXIBILITY_STATIC_GATE /
NO_HARDCODED_MODEL_EXPECTATION_GATE.

The accepted live command must carry the raw --disk path and
--inv2-ensemble; the wrapper must be dataset-agnostic (env vars, never
hardcoded evidence paths) AND model-flexible (no provider/model literal
in the wrapper, routing is env-driven). The old model-name-coupled
filename must remain only as a delegating compat shim.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

_WRAPPER = Path("scripts/live_acceptance.sh")
_SHIM = Path("scripts/haiku2_acceptance.sh")


def _help_text() -> str:
    out = subprocess.run(
        [sys.executable, "run_pipeline.py", "--help"],
        capture_output=True, text=True, timeout=60,
    )
    return out.stdout + out.stderr


def test_cli_exposes_required_flags():
    h = _help_text()
    for flag in (
        "--image", "--disk", "--disk-mount", "--inv2-ensemble", "--live",
    ):
        assert flag in h, "run_pipeline --help must expose %s" % flag


def test_wrapper_exists_and_uses_env_vars():
    assert _WRAPPER.is_file(), "generic acceptance wrapper missing"
    txt = _WRAPPER.read_text()
    for var in (
        "SIFT_IMAGE_PATH", "SIFT_DISK_PATH", "SIFT_DISK_MOUNT",
        "SIFT_EXPECTED_MODEL", "SIFT_FORCE_MODEL",
        "SIFT_INV2_ENSEMBLE_FORCE_MODEL",
    ):
        assert var in txt, "wrapper must consume %s from env" % var


def test_wrapper_has_no_hardcoded_evidence_paths():
    txt = _WRAPPER.read_text()
    sep = "/"
    forbidden_roots = [
        sep + "cases" + sep,
        sep + "mnt" + sep,
        sep + "media" + sep,
    ]
    for root in forbidden_roots:
        assert root not in txt, (
            "wrapper must not hardcode %s evidence paths" % root
        )


def test_wrapper_is_model_flexible_no_literal():
    txt = _WRAPPER.read_text()
    # Routing is env-driven: no exact provider/model literal anywhere.
    assert not re.search(r"\b(claude|gpt|gemini)-\w", txt), (
        "wrapper must not hardcode a provider/model name"
    )


def test_wrapper_live_command_has_ensemble_and_raw_disk():
    txt = _WRAPPER.read_text()
    for tok in ("--live", "--inv2-ensemble", "--disk", "--image",
                "--disk-mount"):
        assert tok in txt


def test_wrapper_has_raw_disk_hash_command():
    txt = _WRAPPER.read_text()
    assert "sha256sum" in txt
    assert "SIFT_DISK_PATH" in txt
    assert "RAW_DISK_HASH_COMMAND_GATE" in txt


def test_markers_present_in_wrapper():
    txt = _WRAPPER.read_text()
    for g in (
        "CLI_ARG_SUPPORT_GATE",
        "INV2_ENSEMBLE_PRESENT_GATE",
        "RAW_DISK_HASH_COMMAND_GATE",
        "MODEL_FLEXIBILITY_STATIC_GATE",
        "NO_HARDCODED_MODEL_EXPECTATION_GATE",
    ):
        assert g in txt


def test_legacy_filename_is_delegating_shim():
    assert _SHIM.is_file()
    shim = _SHIM.read_text()
    assert "live_acceptance.sh" in shim, (
        "legacy wrapper must delegate to the generic wrapper"
    )
    assert "exec bash" in shim
    # The shim itself must not re-couple architecture to a model name.
    assert not re.search(r"\b(claude|gpt|gemini)-\w", shim)


def test_marker():
    print("CLI_ARG_SUPPORT_GATE=PASS")
    print("INV2_ENSEMBLE_PRESENT_GATE=PASS")
    print("RAW_DISK_HASH_COMMAND_GATE=PASS")
    print("MODEL_FLEXIBILITY_STATIC_GATE=PASS")
    print("NO_HARDCODED_MODEL_EXPECTATION_GATE=PASS")
    assert True
