from __future__ import annotations

import importlib
import os
from pathlib import Path


def test_mft_window_fallback_source_markers_present():
    text = Path("src/sift_sentinel/tools/disk.py").read_text(errors="replace")
    assert "SIFT_MFT_WINDOW_FALLBACK_FILTER_V1" in text
    assert "SIFT_MFT_WINDOW_FALLBACK_WRAPPER_V1" in text
    assert "SIFT_MFT_TIMELINE_IGNORE_WINDOW" in text


def test_mft_window_fallback_retries_when_primary_zero(monkeypatch):
    import sift_sentinel.tools.disk as disk

    calls: list[str | None] = []

    def fake_original(*args, **kwargs):
        flag = os.environ.get("SIFT_MFT_TIMELINE_IGNORE_WINDOW")
        calls.append(flag)
        if flag:
            return [{"path": r"C:\Windows\synthetic.txt", "ts": "2020-01-01T00:00:00Z"}]
        return []

    monkeypatch.setattr(disk, "_sift_original_extract_mft_timeline_window_v1", fake_original, raising=False)
    monkeypatch.delenv("SIFT_MFT_TIMELINE_IGNORE_WINDOW", raising=False)

    result = disk.extract_mft_timeline("synthetic-root")
    assert isinstance(result, list)
    assert len(result) == 1
    assert calls == [None, "1"]


def test_mft_window_fallback_preserves_operator_no_window_env(monkeypatch):
    import sift_sentinel.tools.disk as disk

    calls: list[str | None] = []

    def fake_original(*args, **kwargs):
        calls.append(os.environ.get("SIFT_MFT_TIMELINE_IGNORE_WINDOW"))
        return []

    monkeypatch.setattr(disk, "_sift_original_extract_mft_timeline_window_v1", fake_original, raising=False)
    monkeypatch.setenv("SIFT_MFT_TIMELINE_IGNORE_WINDOW", "1")

    result = disk.extract_mft_timeline("synthetic-root")
    assert result == []
    assert calls == ["1"]
