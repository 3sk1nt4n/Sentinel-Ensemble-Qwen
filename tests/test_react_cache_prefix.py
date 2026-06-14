"""Lever 2: ReAct static-prefix prompt caching. The big static block (catalog +
instructions) is marked with cache_control and reused across many ReAct turns;
the per-finding/per-turn content follows uncached. Universal: splits on a
content-neutral sentinel keyed on the static catalog, never on case data.

Two testable units (the live _live_call split lives in the run_pipeline SCRIPT
and is exercised indirectly):
- model_roles.build_cached_message_content -- the pure split helper
- coordinator._build_react_prompt -- static-first reorder under the flag
"""
from __future__ import annotations

from sift_sentinel.model_roles import (
    SIFT_CACHE_BREAK,
    build_cached_message_content,
)


# ── the pure split helper ────────────────────────────────────────────────
def test_no_sentinel_does_not_cache_a_unique_prompt():
    """A prompt with NO cacheable prefix sentinel is a one-shot / finding-first
    prompt: whole-prompt caching only ever WRITES an entry (1.25x) that is never
    read (measured live: ReAct/Inv1/Inv4 wrote ~789K cache tokens, read 0). So
    it must NOT be cached -- plain string, no cache_control. Model-neutral:
    cache_control is metadata; the text the model sees is unchanged."""
    import os
    os.environ.pop("SIFT_CACHE_WHOLE_PROMPT", None)
    out = build_cached_message_content("plain prompt", cache_enabled=True)
    assert out == "plain prompt"


def test_no_sentinel_whole_prompt_cache_is_restorable(monkeypatch):
    monkeypatch.setenv("SIFT_CACHE_WHOLE_PROMPT", "1")
    out = build_cached_message_content("plain prompt", cache_enabled=True)
    assert isinstance(out, list) and len(out) == 1
    assert out[0]["cache_control"] == {"type": "ephemeral"}


def test_sentinel_splits_prefix_and_suffix():
    prompt = "STATIC CATALOG" + SIFT_CACHE_BREAK + "dynamic finding"
    out = build_cached_message_content(prompt, cache_enabled=True)
    assert isinstance(out, list) and len(out) == 2
    assert out[0]["text"] == "STATIC CATALOG"
    assert out[0]["cache_control"] == {"type": "ephemeral"}
    assert out[1]["text"] == "dynamic finding"
    assert "cache_control" not in out[1]                 # suffix uncached
    # the sentinel is never shown to the model
    assert SIFT_CACHE_BREAK not in out[0]["text"]
    assert SIFT_CACHE_BREAK not in out[1]["text"]


def test_cache_disabled_returns_plain_string_and_strips_sentinel():
    prompt = "STATIC" + SIFT_CACHE_BREAK + "dynamic"
    out = build_cached_message_content(prompt, cache_enabled=False)
    assert out == "STATICdynamic"                        # one string, no sentinel


def test_empty_prefix_does_not_emit_a_blank_cached_block():
    import os
    os.environ.pop("SIFT_CACHE_WHOLE_PROMPT", None)
    prompt = SIFT_CACHE_BREAK + "only dynamic"
    out = build_cached_message_content(prompt, cache_enabled=True)
    # a blank prefix is useless to cache -> no cacheable prefix -> plain string
    assert out == "only dynamic"


# ── the ReAct reorder (static-first under the flag) ──────────────────────
def _finding():
    return {"finding_id": "F1", "title": "t", "pid": 1}


def test_react_prompt_default_order_has_finding_before_tools(monkeypatch):
    monkeypatch.delenv("SIFT_REACT_CACHE_PREFIX", raising=False)
    from sift_sentinel.coordinator import _build_react_prompt
    p = _build_react_prompt(_finding(), [], turn=0)
    assert SIFT_CACHE_BREAK not in p
    assert p.index("<finding>") < p.index("<available_tools>")


def test_react_prompt_cache_mode_is_static_first_with_sentinel(monkeypatch):
    monkeypatch.setenv("SIFT_REACT_CACHE_PREFIX", "1")
    from sift_sentinel.coordinator import _build_react_prompt
    p = _build_react_prompt(_finding(), [], turn=0)
    assert SIFT_CACHE_BREAK in p
    # static catalog precedes the sentinel; the per-finding block follows it
    assert p.index("<available_tools>") < p.index(SIFT_CACHE_BREAK)
    assert p.index(SIFT_CACHE_BREAK) < p.index("<finding>")


def test_react_prompt_cache_prefix_is_constant_across_findings(monkeypatch):
    # the cached prefix must be byte-identical for two different findings so the
    # cache actually hits across turns
    monkeypatch.setenv("SIFT_REACT_CACHE_PREFIX", "1")
    from sift_sentinel.coordinator import _build_react_prompt
    a = _build_react_prompt({"finding_id": "A", "title": "x", "pid": 1}, [], 0)
    b = _build_react_prompt({"finding_id": "B", "title": "y", "pid": 2}, [], 0)
    pa = a.split(SIFT_CACHE_BREAK, 1)[0]
    pb = b.split(SIFT_CACHE_BREAK, 1)[0]
    assert pa == pb and len(pa) > 200
