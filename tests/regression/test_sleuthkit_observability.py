from __future__ import annotations

import importlib
from pathlib import Path

import pytest


def test_run_sleuthkit_surfaces_returncode_and_stderr_on_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sift_sentinel.tools.generic as gen

    gen = importlib.reload(gen)

    class Completed:
        returncode = 1
        stdout = ""
        stderr = "Cannot determine file system type"

    captured: list[list[str]] = []

    def fake_run(cmd: list[str], *args: object, **kwargs: object) -> Completed:
        captured.append(cmd)
        return Completed()

    monkeypatch.setattr("subprocess.run", fake_run)

    result = gen.run_sleuthkit("fls", "/tmp/sift-image.E01")

    assert captured
    assert result["tool_name"] == "sleuthkit_fls"
    assert result["record_count"] == 0
    assert result["output"] == []
    assert result["returncode"] == 1
    assert result["failure_mode"] == "runtime_error"
    assert "Cannot determine" in result["error"]
    assert "Cannot determine" in result["stderr_excerpt"]


def test_run_sleuthkit_surfaces_stderr_even_when_returncode_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sift_sentinel.tools.generic as gen

    gen = importlib.reload(gen)

    class Completed:
        returncode = 0
        stdout = ""
        stderr = "Cannot determine file system type"

    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: Completed())

    result = gen.run_sleuthkit("fls", "/tmp/sift-image.E01")

    assert result["record_count"] == 0
    assert result["returncode"] == 0
    assert result["failure_mode"] == "stderr_no_records"
    assert "Cannot determine" in result["error"]


def test_run_sleuthkit_success_retains_output_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sift_sentinel.tools.generic as gen

    gen = importlib.reload(gen)

    class Completed:
        returncode = 0
        stdout = "r/r 1-128-1: file.txt\n"
        stderr = ""

    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: Completed())

    result = gen.run_sleuthkit("fls", "/tmp/sift-image.E01")

    assert result["tool_name"] == "sleuthkit_fls"
    assert result["record_count"] == 1
    assert result["output"] == ["r/r 1-128-1: file.txt"]
    assert result["returncode"] == 0
    assert "failure_mode" not in result
    assert "error" not in result


def test_coordinator_preserves_sleuthkit_failure_metadata(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import sift_sentinel.coordinator as c
    import sift_sentinel.tools.generic as gen

    gen = importlib.reload(gen)
    c = importlib.reload(c)
    c.new_tool_health()

    disk = tmp_path / "disk.E01"
    disk.write_bytes(b"synthetic disk image placeholder")

    monkeypatch.setattr("shutil.which", lambda _command: "/usr/bin/fls")

    def fake_run_sleuthkit(command: str, image_path: str, args: object = None) -> dict:
        return {
            "tool_name": "sleuthkit_fls",
            "output": [],
            "record_count": 0,
            "returncode": 1,
            "failure_mode": "runtime_error",
            "error": "Cannot determine file system type",
            "stderr_excerpt": "Cannot determine file system type",
        }

    monkeypatch.setattr("sift_sentinel.tools.generic.run_sleuthkit", fake_run_sleuthkit)

    result = c.run_selected_tools(
        ["sleuthkit_fls"],
        image_path=str(tmp_path / "memory.img"),
        disk_path=str(disk),
        existing={},
        disk_mount="",
    )

    envelope = result["sleuthkit_fls"]
    assert envelope["record_count"] == 0
    assert envelope["failure_mode"] == "runtime_error"
    assert envelope["returncode"] == 1
    assert "Cannot determine" in envelope["error"]
    assert "Cannot determine" in envelope["stderr_excerpt"]


def test_run_sleuthkit_tsk_recover_order_still_image_before_output_dir(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sift_sentinel.tools.generic as gen

    gen = importlib.reload(gen)
    captured: list[list[str]] = []

    class Completed:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(cmd: list[str], *args: object, **kwargs: object) -> Completed:
        captured.append(cmd)
        return Completed()

    monkeypatch.setattr("subprocess.run", fake_run)

    gen.run_sleuthkit("tsk_recover", "/tmp/sift-image.E01", ["/tmp/sift-output"])

    _tsk = [c for c in captured if c and c[0] == "tsk_recover"]
    assert _tsk and _tsk[0][:3] == ["tsk_recover", "/tmp/sift-image.E01", "/tmp/sift-output"]
