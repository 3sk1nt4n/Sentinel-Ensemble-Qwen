from __future__ import annotations

import os
import subprocess
import sys

from sift_sentinel.analysis.ssdt_runtime_guard import install


def test_ssdt_command_is_time_bounded(monkeypatch):
    monkeypatch.setenv("SIFT_SSDT_TIMEOUT_S", "1")
    install()
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "import time; time.sleep(10)",
            "windows.ssdt.SSDT",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 124
    assert "SIFT_SSDT_RUNTIME_GUARD timeout" in proc.stderr
    assert "health_status=unknown" in proc.stderr


def test_non_ssdt_command_unaffected():
    install()
    proc = subprocess.run(
        [sys.executable, "-c", "print('ok')"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0
    assert proc.stdout.strip() == "ok"


def test_source_no_overconfident_kernel_clean_wording():
    import pathlib

    active = [pathlib.Path("run_pipeline.py")] + list(pathlib.Path("src").rglob("*.py"))
    offenders = []
    for p in active:
        if not p.exists():
            continue
        text = p.read_text(errors="ignore").lower()
        if "kernel is clean" in text:
            offenders.append(str(p))
    assert not offenders
