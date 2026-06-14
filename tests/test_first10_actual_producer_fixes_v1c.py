from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def test_mft_gate_no_arg_source_mode_passes():
    r = subprocess.run(
        [sys.executable, "scripts/check_mft_window_fallback_gate.py"],
        text=True,
        capture_output=True,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "MFT_WINDOW_FALLBACK_SOURCE_GATE=PASS" in r.stdout


def test_volatility_resolver_accepts_active_memory_env(tmp_path, monkeypatch):
    mem = tmp_path / "memory.raw"
    mem.write_bytes(b"fake")
    monkeypatch.setenv("SIFT_ACTIVE_MEMORY_PATH", str(mem))

    from sift_sentinel.analysis.volatility_arg_contract import resolve_volatility_image_path

    assert resolve_volatility_image_path(tool_name="vol_amcache") == str(mem)


def test_volatility_resolver_positional_mapping_compat(tmp_path):
    mem = tmp_path / "memory.raw"
    mem.write_bytes(b"fake")

    from sift_sentinel.analysis.volatility_arg_contract import resolve_volatility_image_path

    assert resolve_volatility_image_path({"image_path": str(mem)}) == str(mem)


def test_mft_resolver_forces_disk_path_even_when_filter_empty(monkeypatch, tmp_path):
    import sift_sentinel.runtime.high_value_tool_args as hv

    mount = tmp_path / "mnt"
    mount.mkdir()
    calls = []

    monkeypatch.setattr(hv, "_mcp_call", lambda name, args: calls.append((name, args)) or {"output": [], "record_count": 0})
    if hasattr(hv, "_filter_tool_args"):
        monkeypatch.setattr(hv, "_filter_tool_args", lambda *a, **k: {})

    result = hv._sift_resolve_extract_mft_timeline_disk_mount_compat_v1c(disk_mount=mount)
    assert calls == [("extract_mft_timeline", {"disk_path": str(mount)})]


def test_mcp_parse_event_logs_local_fallback(monkeypatch):
    import sift_sentinel.mcp_client as mc

    called = {}

    def fake_parse_event_logs(**kwargs):
        called.update(kwargs)
        return {"output": [{"EventID": 4624}], "record_count": 1}

    import sift_sentinel.tools.disk_extended as de
    monkeypatch.setattr(de, "parse_event_logs", fake_parse_event_logs)

    out = mc._sift_local_disk_tool_fallback_v1c(
        "tool_parse_event_logs",
        {"disk_mount": "/tmp/x"},
        "Connection closed",
    )
    assert out["record_count"] == 1
    assert out["sift_mcp_local_fallback"] is True
    assert called["disk_mount"] == "/tmp/x"


def test_rdp_safe_partial_fallback_returns_log_file_records(tmp_path):
    from sift_sentinel.tools.parse_rdp_artifacts import _sift_rdp_safe_partial_records_v1c

    logs = tmp_path / "Windows" / "System32" / "winevt" / "Logs"
    logs.mkdir(parents=True)
    (logs / "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx").write_bytes(b"x")

    recs = _sift_rdp_safe_partial_records_v1c(tmp_path)
    assert recs
    assert any(r.get("artifact_type") == "rdp_related_event_log_file" for r in recs)
