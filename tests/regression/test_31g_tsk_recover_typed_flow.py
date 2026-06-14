"""31G: tsk_recover recovered files must become typed EvidenceDB facts.

Dataset-agnostic: synthetic temp files only. No live evidence, no case paths,
no IPs, no hashes copied from evidence.
"""

from __future__ import annotations

import hashlib
import importlib
from pathlib import Path


def test_tsk_recover_wrapper_inventories_output_dir(monkeypatch, tmp_path):
    import sift_sentinel.tools.generic as gen

    gen = importlib.reload(gen)

    out_dir = tmp_path / "recover-out"
    out_dir.mkdir()
    recovered = out_dir / "Users" / "Public" / "Temp" / "stage_payload.exe"
    recovered.parent.mkdir(parents=True)
    payload = b"MZ synthetic recovered executable sample"
    recovered.write_bytes(payload)

    captured = []

    class Completed:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(cmd, *args, **kwargs):
        captured.append(cmd)
        return Completed()

    monkeypatch.setattr("subprocess.run", fake_run)
    result = gen.run_sleuthkit("tsk_recover", "/tmp/synthetic-disk.E01", [str(out_dir)])

    assert captured
    assert captured[0][:3] == ["tsk_recover", "/tmp/synthetic-disk.E01", str(out_dir)]
    assert result["tool_name"] == "sleuthkit_tsk_recover"
    assert result["record_count"] == 1
    assert len(result["output"]) == 1
    rec = result["output"][0]
    assert rec["path"] == "Users/Public/Temp/stage_payload.exe"
    assert rec["size"] == len(payload)
    assert rec["sha256"] == hashlib.sha256(payload).hexdigest()


def test_tsk_recover_compiler_registered_and_emits_filesystem_fact():
    from sift_sentinel.analysis.evidence_db import _TOOL_COMPILERS

    assert "sleuthkit_tsk_recover" in _TOOL_COMPILERS
    compiler = _TOOL_COMPILERS["sleuthkit_tsk_recover"]

    records = [{
        "path": "Users/Public/Temp/stage_payload.exe",
        "recovered_path": "/tmp/recover-out/Users/Public/Temp/stage_payload.exe",
        "name": "stage_payload.exe",
        "size": 37,
        "sha256": "a" * 64,
        "source": "tsk_recover",
    }]
    emitted = list(compiler(records))

    assert len(emitted) == 1
    idx, fact, reason = emitted[0]
    assert idx == 0
    assert reason is None
    assert fact["fact_type"] == "filesystem_listing_fact"
    assert fact["path"] == "Users/Public/Temp/stage_payload.exe"
    assert fact["recovered_path"].endswith("stage_payload.exe")
    assert fact["sha256"] == "a" * 64
    assert fact["flags"] == "recovered"
    assert "Users/Public/Temp/stage_payload.exe" in fact["index"]["by_path"]
    assert "a" * 64 in fact["index"]["by_hash"]
