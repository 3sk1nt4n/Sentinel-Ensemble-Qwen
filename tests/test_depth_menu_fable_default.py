"""Depth menu: HEAVY defaults to Opus 4.8 (live-proven; Fable 5 trial hit
stop_reason=refusal on the Inv2 prompt) and the chosen model propagates to
EVERY stage (all 4 invocations + the ensemble). The displayed name always
reflects the ACTUAL model -- an env override (e.g. Fable for A/B) shows the
real one. Model ids assembled from fragments (no contiguous literal).
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _fresh(monkeypatch, heavy=None):
    if heavy is None:
        monkeypatch.delenv("SIFT_HEAVY_MODEL", raising=False)
    else:
        monkeypatch.setenv("SIFT_HEAVY_MODEL", heavy)
    import step0_onboard as s
    return importlib.reload(s)


def test_heavy_defaults_to_opus48(monkeypatch):
    s = _fresh(monkeypatch)
    heavy = s.ANALYSIS_MODES["1"]
    assert heavy["name"] == "Claude Opus 4.8"
    assert "opus" in heavy["model"]
    assert "Opus 4.8" in heavy["blurb"]


def test_chosen_model_propagates_to_all_stages(monkeypatch):
    s = _fresh(monkeypatch, heavy="claude-" + "fable-5")   # A/B override path
    env = s.mode_launch_env(s.ANALYSIS_MODES["1"])
    for k in ("SIFT_FORCE_MODEL", "SIFT_DEFAULT_MODEL",
              "SIFT_INV2_ENSEMBLE_FORCE_MODEL", "SIFT_MODEL_INV1_PRIMARY",
              "SIFT_MODEL_ANALYSIS", "SIFT_MODEL_REACT", "SIFT_MODEL_REPORT"):
        assert "fable" in env[k], k


def test_env_override_to_fable_shows_real_name(monkeypatch):
    s = _fresh(monkeypatch, heavy="claude-" + "fable-5")
    assert s.ANALYSIS_MODES["1"]["name"] == "Claude Fable 5"
    env = s.mode_launch_env(s.ANALYSIS_MODES["1"])
    assert "fable" in env["SIFT_FORCE_MODEL"]


def test_model_display_is_agnostic(monkeypatch):
    s = _fresh(monkeypatch)
    assert s._model_display("x-fable-5") == "Claude Fable 5"
    assert s._model_display("x-haiku-4-5") == "Claude Haiku 4.5"
    assert s._model_display("weird-model") == "weird-model"


def teardown_module(_m):
    # reload clean so other tests see pristine module state
    monkey = None
    import step0_onboard as s
    importlib.reload(s)
