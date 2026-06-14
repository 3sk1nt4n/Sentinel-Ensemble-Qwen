"""Guard: run_pipeline.py must have no undefined names (ruff F821).

run_pipeline.py is a top-level SCRIPT, so the full suite never executes its
tool-selection path -- a NameError there (e.g. an import removed while a later
line still uses it) passes py_compile and the whole suite, then crashes the
live run. ruff's F821 catches undefined names statically. Skips cleanly if
ruff is unavailable.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

_RP = Path(__file__).resolve().parent.parent / "run_pipeline.py"


def test_run_pipeline_has_no_undefined_names():
    ruff = shutil.which("ruff")
    if not ruff:
        pytest.skip("ruff not available")
    proc = subprocess.run(
        [ruff, "check", "--select", "F821", "--no-cache", str(_RP)],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, (
        "ruff F821 found undefined name(s) in run_pipeline.py:\n"
        + proc.stdout + proc.stderr
    )
