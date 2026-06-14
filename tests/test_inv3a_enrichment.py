"""D8-A: the inv3a prompt currently shows each ambiguous finding as
'tools=[...] evidence="300 chars"' -- the model adjudicates nearly blind while
the deterministic cross-reference (tool count, artifact-domain spread, weak-vs-
strong signal split, WHY it was parked) is computed upstream and never shown.
Enrichment injects that profile so the model breaks ties WITH evidence.

Adversarial constraints (case-neutrality): the enrichment may contain ONLY
artifact-type letters, integer counts, and reason-grammar prefixes -- never a
filename, drive-letter path, or tool name (those leak case vocabulary the
neutrality regex can't catch). Flag SIFT_INV3A_ENRICH default OFF -> prompt
byte-identical. Synthetic findings only.
"""
import os
import re
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.analysis.inv3a_finalize import (  # noqa: E402
    build_inv3a_prompt,
    build_xref_profiles,
)

_F = [{
    "finding_id": "Z001",
    "description": "synthetic injected region in a fabricated process",
    "source_tools": ["vol_malfind", "vol_pstree", "parse_event_logs"],
    "disposition_reasons": ["gate:confirmed_ineligible[weak_alone]", "benign:uncorroborated_weak_or_history_only"],
}, {
    "finding_id": "Z002",
    "description": "synthetic single-source observation",
    "source_tools": ["vol_malfind"],
    "disposition_reasons": [],
}]


def _resolver_weak(f, db):
    return True, ["rwx_memory_region_with_unusual_protection"]


def test_profiles_counts_and_domains():
    p = build_xref_profiles(_F, evidence_db={"x": 1}, _resolver=_resolver_weak)
    assert p["Z001"]["tools"] == 3
    assert p["Z001"]["domains"] >= 2          # memory + event-log classes
    assert p["Z002"]["tools"] == 1
    assert p["Z002"]["domains"] == 1
    assert p["Z001"]["weak"] == 1 and p["Z001"]["strong"] == 0
    assert p["Z001"]["parked"].startswith("gate:confirmed_ineligible")


def test_prompt_carries_xref_when_enabled():
    p = build_xref_profiles(_F, evidence_db={"x": 1}, _resolver=_resolver_weak)
    prompt = build_inv3a_prompt(_F, profiles=p)
    assert "xref:" in prompt
    assert "tools=3" in prompt
    assert "weak=1" in prompt
    # guidance: the model is told HOW to use the cross-reference
    assert "corroborat" in prompt.lower()


def test_enrichment_is_case_neutral():
    p = build_xref_profiles(_F, evidence_db={"x": 1}, _resolver=_resolver_weak)
    prompt = build_inv3a_prompt(_F, profiles=p)
    # isolate ONLY the xref additions (the rest of the prompt carries the
    # finding's own description by design)
    added = "\n".join(seg for ln in prompt.splitlines()
                      for seg in [ln[ln.find("xref:"):]] if "xref:" in ln)
    assert not re.search(r"[A-Za-z]:\\", added)          # no drive-letter path
    assert not re.search(r"\bvol_[a-z_]+\b", added)      # no tool names
    assert not re.search(r"\.[a-z]{2,4}\b", added)       # no filename token


def test_no_profiles_means_byte_identical_prompt():
    legacy = build_inv3a_prompt(_F)
    assert "xref:" not in legacy
