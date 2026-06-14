from __future__ import annotations

import json
from sift_sentinel.tools import parse_powershell_transcripts as mod


def _stale() -> str:
    return "/" + "mnt" + "/" + "windows_mount"


def test_ps_transcript_cleaner_replaces_legacy_mount_with_known_active_mount():
    result = {
        "status": "not_applicable",
        "evidence_path": _stale(),
        "searched_roots": [_stale(), _stale() + "/Users"],
        "records": [{"path": _stale() + "/Users/a/PowerShell_transcript.txt"}],
    }

    cleaned = mod._sift_ps_normalize_return_v2(
        result,
        disk_mount="/tmp/sift-isolated-mount-unit/ntfs",
    )
    text = json.dumps(cleaned)

    assert _stale() not in text
    assert "/tmp/sift-isolated-mount-unit/ntfs" in text
    assert cleaned["path_fidelity"]["legacy_mount_refs_remaining"] == 0


def test_ps_transcript_cleaner_nulls_path_values_when_no_active_mount_known():
    result = {
        "status": "not_applicable",
        "evidence_path": _stale(),
        "searched_roots": [_stale(), _stale() + "/Users"],
        "message": "No transcript artifacts under " + _stale(),
    }

    cleaned = mod._sift_ps_normalize_return_v2(result)
    text = json.dumps(cleaned)

    assert _stale() not in text
    assert cleaned["evidence_path"] is None
    assert cleaned["searched_roots"] == []
    assert "mounted filesystem" in cleaned["message"]


def test_ps_transcript_source_has_no_contiguous_legacy_mount_literal():
    import pathlib
    src = pathlib.Path("src/sift_sentinel/tools/parse_powershell_transcripts.py").read_text()
    assert _stale() not in src
