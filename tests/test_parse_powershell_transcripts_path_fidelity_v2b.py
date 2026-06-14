from __future__ import annotations

import json
from sift_sentinel.tools import parse_powershell_transcripts as mod


def _stale() -> str:
    return "/" + "mnt" + "/" + "windows_mount"


def test_none_like_mount_env_is_not_used(monkeypatch):
    monkeypatch.setenv("SIFT_ACTIVE_DISK_MOUNT", "None")
    monkeypatch.setenv("SIFT_DISK_MOUNT", "null")
    monkeypatch.setenv("SIFT_DISK_MOUNT_PATH", "unknown")

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
    assert cleaned["message"] == "No transcript artifacts under mounted filesystem"


def test_result_dict_positional_arg_is_not_misread_as_mount(monkeypatch):
    monkeypatch.delenv("SIFT_ACTIVE_DISK_MOUNT", raising=False)
    monkeypatch.delenv("SIFT_DISK_MOUNT", raising=False)
    monkeypatch.delenv("SIFT_DISK_MOUNT_PATH", raising=False)
    monkeypatch.delenv("SIFT_MOUNT_ROOT", raising=False)
    monkeypatch.delenv("SIFT_WINDOWS_MOUNT", raising=False)

    result = {
        "status": "not_applicable",
        "evidence_path": _stale(),
        "records": [],
    }

    cleaned = mod._sift_ps_normalize_return_v2(result, result)
    assert cleaned["evidence_path"] is None
    assert _stale() not in json.dumps(cleaned)


def test_real_isolated_mount_replacement_still_works(monkeypatch):
    monkeypatch.setenv("SIFT_ACTIVE_DISK_MOUNT", "/tmp/sift-isolated-mount-unit/ntfs")

    result = {
        "status": "not_applicable",
        "evidence_path": _stale(),
        "searched_roots": [_stale() + "/Users"],
    }

    cleaned = mod._sift_ps_normalize_return_v2(result)
    text = json.dumps(cleaned)

    assert _stale() not in text
    assert "/tmp/sift-isolated-mount-unit/ntfs" in text
