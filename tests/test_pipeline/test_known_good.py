"""Tests for optional operator-provided process context."""

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


def _reload_known_good():
    import sift_sentinel.known_good as kg
    return importlib.reload(kg)


def test_default_known_good_registry_empty():
    kg = _reload_known_good()
    assert kg.KNOWN_GOOD_PROCESSES == {}
    assert kg.render_known_good_block() == ""


def test_default_flag_known_good_marks_no_findings():
    kg = _reload_known_good()

    findings = [{
        "artifact": "sample.exe",
        "claims": [{"type": "pid", "pid": 1234, "process": "sample.exe"}],
    }]

    result = kg.flag_known_good(findings)

    assert result[0]["known_good"] is False
    assert result[0]["known_good_note"] == ""


def test_file_path_without_enable_flag_is_ignored(tmp_path, monkeypatch):
    allow = tmp_path / "allow.json"
    allow.write_text(json.dumps({"sample.exe": "local operator context"}))

    monkeypatch.setenv("SIFT_KNOWN_GOOD_FILE", str(allow))
    kg = _reload_known_good()

    assert kg.KNOWN_GOOD_PROCESSES == {}
    assert kg.render_known_good_block() == ""


def test_external_known_good_file_loads_with_double_opt_in(tmp_path, monkeypatch):
    allow = tmp_path / "allow.json"
    allow.write_text(json.dumps({"sample.exe": "local operator context"}))

    monkeypatch.setenv("SIFT_ENABLE_KNOWN_GOOD", "1")
    monkeypatch.setenv("SIFT_KNOWN_GOOD_FILE", str(allow))
    kg = _reload_known_good()

    assert kg.KNOWN_GOOD_PROCESSES == {"sample.exe": "local operator context"}

    block = kg.render_known_good_block()
    assert "sample.exe" in block
    assert "local operator context" in block
    assert "non-evidentiary" in block
    assert "not be used to dismiss" in block


def test_external_context_can_annotate_but_not_remove(tmp_path, monkeypatch):
    allow = tmp_path / "allow.json"
    allow.write_text(json.dumps({"sample.exe": "local operator context"}))

    monkeypatch.setenv("SIFT_ENABLE_KNOWN_GOOD", "1")
    monkeypatch.setenv("SIFT_KNOWN_GOOD_FILE", str(allow))
    kg = _reload_known_good()

    findings = [
        {
            "artifact": "sample.exe",
            "claims": [{"type": "pid", "pid": 1234, "process": "sample.exe"}],
        },
        {
            "artifact": "other.exe",
            "claims": [{"type": "pid", "pid": 9004, "process": "other.exe"}],
        },
    ]

    result = kg.flag_known_good(findings)

    assert len(result) == 2
    assert result[0]["known_good"] is True
    assert result[0]["known_good_note"] == "local operator context"
    assert result[1]["known_good"] is False
    assert result[1]["known_good_note"] == ""


def test_invalid_external_file_fails_closed(tmp_path, monkeypatch):
    allow = tmp_path / "allow.json"
    allow.write_text("{not json")

    monkeypatch.setenv("SIFT_ENABLE_KNOWN_GOOD", "1")
    monkeypatch.setenv("SIFT_KNOWN_GOOD_FILE", str(allow))
    kg = _reload_known_good()

    assert kg.KNOWN_GOOD_PROCESSES == {}
    assert kg.render_known_good_block() == ""
