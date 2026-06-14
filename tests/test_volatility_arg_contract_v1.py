from __future__ import annotations

import sys
from pathlib import Path

from sift_sentinel.analysis.volatility_arg_contract import (
    resolve_volatility_image_path,
    normalize_volatility_call_kwargs,
)


def test_resolves_memory_image_from_env(tmp_path, monkeypatch):
    mem = tmp_path / "case-memory.img"
    mem.write_bytes(b"memory")
    monkeypatch.setenv("SIFT_MEMORY_IMAGE", str(mem))
    assert resolve_volatility_image_path(tool_name="vol_amcache") == str(mem)


def test_rejects_bad_pseudo_values_and_disk_images(tmp_path, monkeypatch):
    disk = tmp_path / "case.E01"
    disk.write_bytes(b"disk")
    monkeypatch.setenv("SIFT_MEMORY_IMAGE", "None")
    assert resolve_volatility_image_path(tool_name="vol_amcache") is None
    assert resolve_volatility_image_path(argv=["run_pipeline.py", "--disk", str(disk)]) is None


def test_resolves_from_sys_argv_memory_flag(tmp_path):
    mem = tmp_path / "memory.raw"
    mem.write_bytes(b"memory")
    got = resolve_volatility_image_path(argv=["run_pipeline.py", "--memory", str(mem)])
    assert got == str(mem)


def test_normalize_volatility_call_kwargs_adds_image_fields(tmp_path, monkeypatch):
    mem = tmp_path / "sample.vmem"
    mem.write_bytes(b"memory")
    monkeypatch.setenv("SIFT_MEMORY_PATH", str(mem))
    got = normalize_volatility_call_kwargs(tool_name="vol_amcache", kwargs={})
    assert got["image_path"] == str(mem)
    assert got["memory_path"] == str(mem)


def test_common_runtime_guard_is_present():
    common = Path("src/sift_sentinel/tools/common.py").read_text(errors="replace")
    assert "SIFT_VOLATILITY_ARG_CONTRACT_COMMON_INJECTION_V1" in common
    assert "resolve_volatility_image_path" in common
