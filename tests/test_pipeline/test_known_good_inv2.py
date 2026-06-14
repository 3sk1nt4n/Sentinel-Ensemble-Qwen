"""Inv2 prompt behavior for optional operator process context."""

from __future__ import annotations

import importlib
import json

import pytest


@pytest.fixture(autouse=True)
def reset_known_good_env(monkeypatch):
    monkeypatch.delenv("SIFT_ENABLE_KNOWN_GOOD", raising=False)
    monkeypatch.delenv("SIFT_KNOWN_GOOD_FILE", raising=False)
    import sift_sentinel.known_good as kg
    importlib.reload(kg)
    yield
    monkeypatch.delenv("SIFT_ENABLE_KNOWN_GOOD", raising=False)
    monkeypatch.delenv("SIFT_KNOWN_GOOD_FILE", raising=False)
    importlib.reload(kg)


def _reload_modules():
    import sift_sentinel.known_good as kg
    import sift_sentinel.prompts as prompts
    kg = importlib.reload(kg)
    prompts = importlib.reload(prompts)
    return kg, prompts


def test_known_good_block_empty_by_default():
    kg, _ = _reload_modules()
    assert kg.KNOWN_GOOD_PROCESSES == {}
    assert kg.render_known_good_block() == ""


def test_inv2_prompt_has_no_operator_context_by_default():
    _, prompts = _reload_modules()
    prompt = prompts.compose_inv2_system_prompt()
    assert "OPERATOR-PROVIDED PROCESS CONTEXT" not in prompt


def test_inv2_prompt_includes_external_context_when_enabled(tmp_path, monkeypatch):
    allow = tmp_path / "allow.json"
    allow.write_text(json.dumps({"sample.exe": "local operator context"}))

    monkeypatch.setenv("SIFT_ENABLE_KNOWN_GOOD", "1")
    monkeypatch.setenv("SIFT_KNOWN_GOOD_FILE", str(allow))

    _, prompts = _reload_modules()
    prompt = prompts.compose_inv2_system_prompt()

    assert "OPERATOR-PROVIDED PROCESS CONTEXT" in prompt
    assert "sample.exe" in prompt
    assert "local operator context" in prompt
    assert "not be used to dismiss" in prompt
