"""31J-alpha: run_pipeline Step6 local worker-count helper has no hidden 8 cap.

The live pipeline path has its own local helper inside run_pipeline.py.
This test parses that helper directly so the contract is checked without
running live evidence or importing the whole CLI entrypoint.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path


def _load_worker_helper():
    text = Path("run_pipeline.py").read_text(errors="ignore")
    tree = ast.parse(text)

    funcs = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "_slot31d_worker_count"
    ]
    assert len(funcs) == 1

    module = ast.Module(body=[funcs[0]], type_ignores=[])
    ast.fix_missing_locations(module)

    class _Logger:
        def warning(self, *args, **kwargs):
            return None

    namespace = {
        "_slot31d_os": os,
        "logger": _Logger(),
    }
    exec(compile(module, "<slot31d_worker_count_test>", "exec"), namespace)
    return namespace["_slot31d_worker_count"]


def test_env_10_with_many_unique_tools_uses_10_workers(monkeypatch):
    fn = _load_worker_helper()
    monkeypatch.setenv("SIFT_STEP6_MAX_WORKERS", "10")
    assert fn(28) == 10


def test_default_with_many_unique_tools_uses_10_workers(monkeypatch):
    fn = _load_worker_helper()
    monkeypatch.delenv("SIFT_STEP6_MAX_WORKERS", raising=False)
    assert fn(28) == 10


def test_invalid_env_falls_back_to_10_not_8(monkeypatch):
    fn = _load_worker_helper()
    monkeypatch.setenv("SIFT_STEP6_MAX_WORKERS", "bad")
    assert fn(28) == 10


def test_worker_count_never_exceeds_unique_task_count(monkeypatch):
    fn = _load_worker_helper()
    monkeypatch.setenv("SIFT_STEP6_MAX_WORKERS", "10")
    assert fn(2) == 2
    assert fn(1) == 1
    assert fn(0) == 1


def test_env_override_above_default_is_respected(monkeypatch):
    fn = _load_worker_helper()
    monkeypatch.setenv("SIFT_STEP6_MAX_WORKERS", "12")
    assert fn(28) == 12
