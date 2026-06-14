"""Slot 31H-alpha TASK 1 -- entity truth package CLI.

Proves the package builds via the module CLI and the shell wrapper,
not just the Python API. dataset-agnostic by construction.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from _etp_fixture import make_synthetic_run

from sift_sentinel.entity_truth_package import (
    ACCEPTANCE_MANIFEST_JSON,
    DURABLE_ENTITY_TRUTH_PACKAGE_GATE,
    PACKAGE_GATES,
)

_REPO = Path(__file__).resolve().parents[2]


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = "src" + (
        os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def test_module_cli_builds_package_and_reports_gates(tmp_path):
    run_json = make_synthetic_run(tmp_path)
    out = tmp_path / "pkg"
    proc = subprocess.run(
        [sys.executable, "-m", "sift_sentinel.entity_truth_package",
         str(run_json), "--output-dir", str(out)],
        cwd=str(_REPO), env=_env(), capture_output=True, text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert (out / ACCEPTANCE_MANIFEST_JSON).is_file()

    printed = {}
    for line in proc.stdout.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            printed[k.strip()] = v.strip()
    for g in PACKAGE_GATES:
        assert printed.get(g) == "PASS", (g, printed.get(g))
    assert printed[DURABLE_ENTITY_TRUTH_PACKAGE_GATE] == "PASS"


def test_module_cli_missing_run_json_fails_cleanly(tmp_path):
    proc = subprocess.run(
        [sys.executable, "-m", "sift_sentinel.entity_truth_package",
         str(tmp_path / "does_not_exist.json")],
        cwd=str(_REPO), env=_env(), capture_output=True, text=True,
        timeout=60,
    )
    assert proc.returncode == 2
    assert "not found" in proc.stderr.lower()


def test_shell_wrapper_builds_package(tmp_path):
    run_json = make_synthetic_run(tmp_path)
    out = tmp_path / "pkg_sh"
    script = _REPO / "scripts" / "build_entity_truth_package.sh"
    proc = subprocess.run(
        ["bash", str(script), str(run_json), str(out)],
        cwd=str(_REPO), env=_env(), capture_output=True, text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert (out / ACCEPTANCE_MANIFEST_JSON).is_file()
