"""P1: provenance-aware RWX corroboration (SIFT_PROVENANCE_RWX, default OFF).

Since vol_ldrmodules began emitting memory_injection_fact, an RWX finding can
be 'corroborated' by the unbacked-module signal even when BOTH the RWX VAD and
the unbacked module trace to a single memory tool -- one observation counted
twice. Under the flag, the unbacked-module signal counts as an INDEPENDENT
corroborator only when a second injection-capable memory method is present.

This is the only gate that can suppress a true positive, so it is OFF by
default and OFF behaviour must be byte-identical to the existing gate.
Universal: keyed on registered signal names + memory-tool provenance, no
case-specific values.
"""
from __future__ import annotations

from sift_sentinel.analysis.disposition import (
    _rwx_uncorroborated,
    rwx_uncorroborated_for_finding,
)

_RWX = "rwx_memory_region_with_unusual_protection"
_UNBACKED = "injected_pe_image_in_executable_memory"
_HOLLOW = "process_hollowing_indicators"


def _f(signals, tools):
    return {"finding_id": "F1", "source_tools": list(tools),
            "claims": [{"type": "pid", "pid": 7}]}


# ── default OFF: identical to the existing signal-only gate ───────────────

def test_off_matches_legacy_gate(monkeypatch):
    monkeypatch.delenv("SIFT_PROVENANCE_RWX", raising=False)
    for sigs, tools in [
        ({_RWX}, ["vol_malfind"]),                       # weak-alone
        ({_RWX, _UNBACKED}, ["vol_ldrmodules"]),         # legacy: corroborated
        ({_RWX, _HOLLOW}, ["vol_malfind", "vol_psxview"]),
        ({_RWX, _UNBACKED}, ["vol_malfind", "vol_ldrmodules"]),
    ]:
        legacy = _rwx_uncorroborated(True, sigs)
        pv = rwx_uncorroborated_for_finding(_f(sigs, tools), True, sigs)
        assert pv == legacy, (sigs, tools, legacy, pv)


# ── ON: single-tool unbacked-module self-corroboration is rejected ────────

def test_on_unbacked_only_single_tool_is_uncorroborated(monkeypatch):
    monkeypatch.setenv("SIFT_PROVENANCE_RWX", "1")
    f = _f({_RWX, _UNBACKED}, ["vol_ldrmodules"])
    assert rwx_uncorroborated_for_finding(f, True, {_RWX, _UNBACKED}) is True


def test_on_unbacked_with_second_method_still_corroborated(monkeypatch):
    monkeypatch.setenv("SIFT_PROVENANCE_RWX", "1")
    # malfind (RWX) + ldrmodules (unbacked) = two independent memory methods
    f = _f({_RWX, _UNBACKED}, ["vol_malfind", "vol_ldrmodules"])
    assert rwx_uncorroborated_for_finding(f, True, {_RWX, _UNBACKED}) is False


def test_on_independent_corroborator_not_suppressed(monkeypatch):
    monkeypatch.setenv("SIFT_PROVENANCE_RWX", "1")
    # a genuinely independent corroborator (hollowing) is untouched even with
    # one tool listed -- the provenance check only scopes the unbacked-module
    # self-corroboration case
    f = _f({_RWX, _HOLLOW}, ["vol_malfind"])
    assert rwx_uncorroborated_for_finding(f, True, {_RWX, _HOLLOW}) is False


def test_on_non_rwx_finding_untouched(monkeypatch):
    monkeypatch.setenv("SIFT_PROVENANCE_RWX", "1")
    f = _f({_HOLLOW}, ["vol_ldrmodules"])
    assert rwx_uncorroborated_for_finding(f, True, {_HOLLOW}) is False


def test_metamorphic_tool_label_irrelevant(monkeypatch):
    monkeypatch.setenv("SIFT_PROVENANCE_RWX", "1")
    a = rwx_uncorroborated_for_finding(
        _f({_RWX, _UNBACKED}, ["vol_ldrmodules"]), True, {_RWX, _UNBACKED})
    b = rwx_uncorroborated_for_finding(
        _f({_RWX, _UNBACKED}, ["VOL_LDRMODULES"]), True, {_RWX, _UNBACKED})
    assert a is b is True
