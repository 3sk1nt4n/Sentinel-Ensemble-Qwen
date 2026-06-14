from __future__ import annotations

import importlib
from pathlib import Path

import pytest


def test_direct_tsk_recover_resolver_returns_mcp_call_with_output_dir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import sift_sentinel.runtime.high_value_tool_args as hv

    hv = importlib.reload(hv)
    output_base = tmp_path / "recover-base"
    artifact = tmp_path / "disk-image.E01"
    artifact.write_bytes(b"synthetic resolver input only")

    monkeypatch.setenv("SIFT_TSK_RECOVER_OUTPUT_BASE", str(output_base))

    first = hv._resolve_sleuthkit_tsk_recover(artifact)
    second = hv._resolve_sleuthkit_tsk_recover(artifact)

    assert first == second
    assert first["kind"] == "mcp_call"
    assert first["tool_name"] == "sleuthkit_tsk_recover"
    assert set(first["args"]) == {"output_dir"}

    output_dir = Path(first["args"]["output_dir"])
    assert output_dir.is_dir()
    assert output_dir.parent == output_base
    assert output_dir.name


def test_resolve_high_value_tool_invocation_maps_tsk_recover_to_output_dir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import sift_sentinel.runtime.high_value_tool_args as hv

    hv = importlib.reload(hv)
    output_base = tmp_path / "recover-output"
    artifact = tmp_path / "disk-image.E01"
    artifact.write_bytes(b"synthetic resolver input only")

    monkeypatch.setenv("SIFT_TSK_RECOVER_OUTPUT_BASE", str(output_base))

    resolved = hv.resolve_high_value_tool_invocation(
        "tool_sleuthkit_tsk_recover",
        image_path=tmp_path / "memory.img",
        disk_path=artifact,
        disk_mount=tmp_path / "mount",
        tool_outputs={},
    )

    assert resolved is not None
    assert resolved["kind"] == "mcp_call"
    assert resolved["tool_name"] == "sleuthkit_tsk_recover"
    assert set(resolved["args"]) == {"output_dir"}

    output_dir = Path(resolved["args"]["output_dir"])
    assert output_dir.is_dir()
    assert output_dir.parent == output_base
    assert "sleuthkit_tsk_recover" in hv.HIGH_VALUE_TOOLS


def test_dispatcher_no_longer_fails_tsk_recover_missing_output_dir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import sift_sentinel.coordinator as c
    import sift_sentinel.runtime.high_value_tool_args as hv

    hv = importlib.reload(hv)
    c = importlib.reload(c)
    c.new_tool_health()

    output_base = tmp_path / "dispatcher-recover-output"
    artifact = tmp_path / "disk-image.E01"
    artifact.write_bytes(b"synthetic dispatcher input only")

    monkeypatch.setenv("SIFT_TSK_RECOVER_OUTPUT_BASE", str(output_base))
    monkeypatch.setattr("shutil.which", lambda _command: "/usr/bin/tsk_recover")

    calls: list[tuple[str, str, object]] = []

    def fake_run_sleuthkit(command: str, image_path: str, args: object = None) -> dict:
        calls.append((command, image_path, args))
        return {
            "tool_name": "sleuthkit_tsk_recover",
            "record_count": 0,
            "records": [],
            "observed_args": args,
        }

    monkeypatch.setattr("sift_sentinel.tools.generic.run_sleuthkit", fake_run_sleuthkit)

    result = c.run_selected_tools(
        ["sleuthkit_tsk_recover"],
        image_path=str(tmp_path / "memory.img"),
        disk_path=str(artifact),
        existing={},
        disk_mount="",
    )

    envelope = result["sleuthkit_tsk_recover"]
    assert envelope.get("failure_mode") != "missing_required_args"
    assert "requires" not in str(envelope).lower()
    assert calls

    observed_args = calls[0][2]
    assert isinstance(observed_args, list)
    assert len(observed_args) == 1
    assert str(output_base) in observed_args[0]


def test_run_sleuthkit_tsk_recover_orders_image_before_output_dir(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sift_sentinel.tools.generic as gen

    gen = importlib.reload(gen)
    captured: list[list[str]] = []

    class Completed:
        returncode = 0
        stdout = "fake stdout"
        stderr = ""

    def fake_run(cmd: list[str], *args: object, **kwargs: object) -> Completed:
        captured.append(cmd)
        return Completed()

    monkeypatch.setattr("subprocess.run", fake_run)

    gen.run_sleuthkit(
        "tsk_recover",
        "/tmp/sift-sentinel-image.E01",
        ["/tmp/sift-sentinel-output-dir"],
    )

    assert captured
    assert captured[0][:3] == [
        "tsk_recover",
        "/tmp/sift-sentinel-image.E01",
        "/tmp/sift-sentinel-output-dir",
    ]


def test_run_sleuthkit_generic_tools_keep_args_before_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sift_sentinel.tools.generic as gen

    gen = importlib.reload(gen)
    captured: list[list[str]] = []

    class Completed:
        returncode = 0
        stdout = "fake stdout"
        stderr = ""

    def fake_run(cmd: list[str], *args: object, **kwargs: object) -> Completed:
        captured.append(cmd)
        return Completed()

    monkeypatch.setattr("subprocess.run", fake_run)

    gen.run_sleuthkit(
        "fls",
        "/tmp/sift-sentinel-image.E01",
        ["-r"],
    )

    assert captured
    assert captured[0][:3] == [
        "fls",
        "-r",
        "/tmp/sift-sentinel-image.E01",
    ]


def test_resolver_returns_not_applicable_for_missing_artifact(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import sift_sentinel.runtime.high_value_tool_args as hv

    hv = importlib.reload(hv)
    monkeypatch.setenv("SIFT_TSK_RECOVER_OUTPUT_BASE", str(tmp_path / "recover-output"))

    resolved = hv.resolve_high_value_tool_invocation(
        "sleuthkit_tsk_recover",
        disk_path=tmp_path / "missing.E01",
    )

    assert resolved is not None
    assert resolved["kind"] == "not_applicable"
    assert resolved["tool_name"] == "sleuthkit_tsk_recover"
    assert "not present" in resolved["reason"].lower()
