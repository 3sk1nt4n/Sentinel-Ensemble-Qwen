"""Structural guards for the run_pipeline.py wirings of the A+++ fixes.

run_pipeline.py is a top-level script (importing it executes the pipeline), so
these guards read it as TEXT -- the same pattern as
test_commit23_confidence_field_name. They assert the four wirings are present,
each behind its kill-switch, and that U1's cache_control was applied ONLY to
the Anthropic LIVE branch (not the GPT/Gemini/Ollama branches).
"""
from __future__ import annotations

from pathlib import Path

_SRC = (Path(__file__).resolve().parent.parent / "run_pipeline.py").read_text()


def test_xcorr_prepass_wired_before_calibration():
    assert "enrich_findings_with_xcorr(" in _SRC
    i_x = _SRC.index("enrich_findings_with_xcorr(")
    i_cal = _SRC.index("findings_final = step_13_calibrate(")
    assert i_x < i_cal, "XCORR must run before step_13_calibrate"
    assert 'if "_evdb" in globals()' in _SRC          # uses in-memory evdb


def test_u1_prompt_cache_gated_and_live_only():
    # REACT_PREFIX_CACHE_V1 refactor: the LIVE branch now builds its content via
    # the shared model_roles.build_cached_message_content helper (which owns the
    # cache_control + sentinel split), still gated on SIFT_PROMPT_CACHE. The
    # invariant preserved: caching applies ONLY to the Anthropic LIVE branch --
    # the GPT/Gemini/Ollama branches keep a plain string content.
    assert 'os.environ.get("SIFT_PROMPT_CACHE"' in _SRC
    assert "build_cached_message_content(" in _SRC
    assert "cache_enabled=" in _SRC
    # the GPT/Gemini/Ollama branches keep a plain string content
    assert _SRC.count('"content": prompt') >= 1
    # the cache_control literal moved into the shared helper, not this script
    assert _SRC.count('"cache_control": {"type": "ephemeral"}') == 0
    _mr = (Path(__file__).resolve().parent.parent
           / "src" / "sift_sentinel" / "model_roles.py").read_text()
    assert '"cache_control": {"type": "ephemeral"}' in _mr


def test_t2_step10_reuses_in_memory_evdb():
    assert "_step10_evdb = _evdb" in _SRC


def test_xbucket_dedup_gated_default_off():
    assert "dedup_cross_bucket as _dedup_cross_bucket" in _SRC
    assert 'os.environ.get("SIFT_XBUCKET_DEDUP"' in _SRC
    # partition-gate discipline: merged ids drop from findings_final
    i_led = _SRC.index("_xbucket_ledger")
    assert "findings_final = [f for f in findings_final" in _SRC[i_led:]
