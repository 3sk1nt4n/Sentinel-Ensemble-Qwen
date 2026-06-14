"""Slot 31F-alpha TASK 6 -- entity report summary.

ENTITY_REPORT_SUMMARY_GATE + NO_DUPLICATE_CONFIRMED_ENTITY_HEADLINE_GATE.
Synthetic fixtures only.
"""
from __future__ import annotations

import re

from sift_sentinel.entities import (
    ENTITY_REPORT_SUMMARY_GATE,
    NO_DUPLICATE_CONFIRMED_ENTITY_HEADLINE_GATE,
    build_entity_truth,
    render_entity_summary_section,
)


def _buckets():
    return {
        "confirmed_malicious_atomic": [
            {"finding_id": "FIXTURE_F1", "severity": "CRITICAL",
             "claims": [{"type": "hash", "sha1": "fixshared"}]},
            {"finding_id": "FIXTURE_F2", "severity": "CRITICAL",
             "claims": [{"type": "hash", "sha1": "fixshared"}]},
            {"finding_id": "FIXTURE_F3", "severity": "CRITICAL",
             "claims": [{"type": "hash", "sha1": "fixshared"}]},
        ],
        "suspicious_needs_review": [
            {"finding_id": "FIXTURE_S1", "pid": 91900,
             "process": "FIXTURE_s.exe", "severity": "HIGH",
             "claims": [{"type": "pid", "pid": 91900}]}],
        "benign_or_false_positive": [],
        "inconclusive_unresolved": [],
        "synthesis_narrative": [],
    }


def test_gate_identifiers_stable():
    assert ENTITY_REPORT_SUMMARY_GATE == "ENTITY_REPORT_SUMMARY_GATE"
    assert NO_DUPLICATE_CONFIRMED_ENTITY_HEADLINE_GATE == \
        "NO_DUPLICATE_CONFIRMED_ENTITY_HEADLINE_GATE"


def test_section_is_additive_and_has_required_lines():
    et = build_entity_truth(_buckets(), react_conflicts=None)
    section = render_entity_summary_section(et)
    assert "## ENTITY-LEVEL SUMMARY" in section
    assert "### Confirmed malicious entities" in section
    assert "### High-priority suspicious entities" in section
    assert "### Contradicted entities requiring tiebreaker" in section
    assert "Confirmed atomic finding count: 3" in section
    assert "Confirmed atomic entity count: 1" in section
    assert "Confirmed atomic compression ratio: 0.3333" in section


def test_no_duplicate_confirmed_entity_headline():
    et = build_entity_truth(_buckets(), react_conflicts=None)
    section = render_entity_summary_section(et)
    # Confirmed sub-section body only.
    body = section.split("### Confirmed malicious entities", 1)[1]
    body = body.split("### High-priority suspicious entities", 1)[0]
    headers = re.findall(r"^- `([^`]+)`", body, re.MULTILINE)
    assert len(headers) == len(set(headers))
    assert len(headers) == et["confirmed_atomic_entity_count"]
    # The three source findings appear under the single entity header,
    # never as separate headers.
    assert "FIXTURE_F1" in body and "FIXTURE_F2" in body \
        and "FIXTURE_F3" in body


def test_empty_confirmed_renders_none():
    buckets = {
        "confirmed_malicious_atomic": [],
        "suspicious_needs_review": [],
        "benign_or_false_positive": [],
        "inconclusive_unresolved": [],
        "synthesis_narrative": [],
    }
    et = build_entity_truth(buckets, react_conflicts=None)
    section = render_entity_summary_section(et)
    body = section.split("### Confirmed malicious entities", 1)[1]
    body = body.split("### High-priority suspicious entities", 1)[0]
    assert "(none)" in body
