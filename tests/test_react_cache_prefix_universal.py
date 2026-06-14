"""The ReAct prompt-cache prefix MUST be universal (case-neutral), never
case-specific.

REACT_PREFIX_CACHE_V1 (SIFT_REACT_CACHE_PREFIX) reorders the ReAct prompt so a
run-constant static block (instructions + tool catalog + OS label + coverage +
escalation rules) is emitted FIRST and cached across every turn/finding, with
the per-finding/per-turn content after the ``<<<SIFT_CACHE_BREAK_V1>>>``
sentinel. For Anthropic prefix caching to ever hit -- and to be safe -- the
cached prefix must contain NO case data: no finding JSON, no PID, no previous
results. If any case data leaked into the prefix, the cache would key on it
(never hit) AND the run would be embedding case specifics where they do not
belong.

These guards LOCK that invariant so a future edit cannot move case data above
the sentinel:

  1. The cached prefix is BYTE-IDENTICAL for two completely different findings
     (the definitive proof that it holds zero case data).
  2. A unique finding marker / PID / previous-result marker appears ONLY in the
     uncached suffix, never in the cached prefix.
  3. Default OFF reproduces the legacy finding-first ordering with no sentinel
     (no verdict-shifting reorder unless explicitly opted in).

Universal: structural segment-boundary assertions, no case data of our own.
Kill-switch SIFT_REACT_CACHE_PREFIX (0/unset = off).
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.coordinator import _build_react_prompt          # noqa: E402
from sift_sentinel.model_roles import SIFT_CACHE_BREAK             # noqa: E402


def _finding(fid, marker, pid):
    return {
        "finding_id": fid,
        "description": marker,
        "severity": "MEDIUM",
        "claims": [{"type": "pid", "pid": pid}],
    }


def _prev(marker, pid):
    return [{
        "turn": 1, "tool": "vol_pslist", "pid": pid,
        "result_count": 3, "reasoning": marker, "result_sample": [{"a": 1}],
    }]


def test_cached_prefix_is_identical_across_different_findings(monkeypatch):
    """The definitive universality proof: same cached prefix for two unrelated
    findings => the prefix carries zero case data."""
    monkeypatch.setenv("SIFT_REACT_CACHE_PREFIX", "1")
    a = _build_react_prompt(_finding("F001", "ALPHA_MARKER_AAA", 111111),
                            _prev("PREV_AAA", 111111), turn=1)
    b = _build_react_prompt(_finding("F999", "OMEGA_MARKER_ZZZ", 999999),
                            _prev("PREV_ZZZ", 999999), turn=1)
    assert SIFT_CACHE_BREAK in a and SIFT_CACHE_BREAK in b
    prefix_a = a.split(SIFT_CACHE_BREAK, 1)[0]
    prefix_b = b.split(SIFT_CACHE_BREAK, 1)[0]
    assert prefix_a == prefix_b, "cached ReAct prefix differs between findings => it leaks case data"


def test_case_data_is_confined_to_the_uncached_suffix(monkeypatch):
    monkeypatch.setenv("SIFT_REACT_CACHE_PREFIX", "1")
    p = _build_react_prompt(_finding("F042", "ZZUNIQUEMARKERZZ", 919191),
                            _prev("SECRETPREVMARKER", 919191), turn=2)
    prefix, _, suffix = p.partition(SIFT_CACHE_BREAK)

    # the run-constant static block IS in the cached prefix
    assert "<available_tools>" in prefix
    assert "senior DFIR analyst" in prefix

    # NO case data may appear in the cached prefix
    for case_token in ("ZZUNIQUEMARKERZZ", "919191", "SECRETPREVMARKER",
                       "<finding>", "<previous_investigation_results>"):
        assert case_token not in prefix, f"case token {case_token!r} leaked into cached prefix"

    # the case data lives in the uncached suffix
    assert "ZZUNIQUEMARKERZZ" in suffix
    assert "919191" in suffix
    assert "SECRETPREVMARKER" in suffix


def test_default_off_has_no_sentinel_and_is_finding_first(monkeypatch):
    monkeypatch.delenv("SIFT_REACT_CACHE_PREFIX", raising=False)
    p = _build_react_prompt(_finding("F007", "LEGACYMARKER", 222222),
                            _prev("LEGACYPREV", 222222), turn=1)
    assert SIFT_CACHE_BREAK not in p
    # finding still present (legacy byte-for-byte ordering), finding before tools
    assert "LEGACYMARKER" in p
    assert p.index("<finding>") < p.index("<available_tools>")


def test_kill_switch_zero_behaves_like_off(monkeypatch):
    monkeypatch.setenv("SIFT_REACT_CACHE_PREFIX", "0")
    p = _build_react_prompt(_finding("F008", "KSMARKER", 333333), None, turn=1)
    assert SIFT_CACHE_BREAK not in p
    assert "KSMARKER" in p
