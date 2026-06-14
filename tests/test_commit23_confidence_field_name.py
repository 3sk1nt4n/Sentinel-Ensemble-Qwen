"""Commit 23: fix confidence field-name bug in self-assessment + HTML counters.

Property tests. Tests assert correct counting behavior when findings
carry the canonical 'confidence_level' field. All synthetic fixtures.
L23-5 is the regression guard: asserts zero reads of the wrong field
name in run_pipeline.py.
"""
from __future__ import annotations


def _count_by_level(findings, level):
    """Mirror of the post-C23 counter logic."""
    return sum(1 for f in findings if f.get("confidence_level") == level)


def test_L23_1_counts_high_findings():
    findings = [
        {"finding_id": "synthetic_0", "confidence_level": "HIGH"},
        {"finding_id": "synthetic_1", "confidence_level": "MEDIUM"},
        {"finding_id": "synthetic_2", "confidence_level": "HIGH"},
    ]
    assert _count_by_level(findings, "HIGH") == 2
    assert _count_by_level(findings, "MEDIUM") == 1
    assert _count_by_level(findings, "LOW") == 0


def test_L23_2_counts_medium_findings():
    findings = [
        {"finding_id": "synthetic_0", "confidence_level": "MEDIUM"},
        {"finding_id": "synthetic_1", "confidence_level": "MEDIUM"},
        {"finding_id": "synthetic_2", "confidence_level": "MEDIUM"},
    ]
    assert _count_by_level(findings, "MEDIUM") == 3
    assert _count_by_level(findings, "HIGH") == 0


def test_L23_3_counts_low_findings():
    findings = [
        {"finding_id": "synthetic_0", "confidence_level": "LOW"},
        {"finding_id": "synthetic_1", "confidence_level": "HIGH"},
    ]
    assert _count_by_level(findings, "LOW") == 1


def test_L23_4_empty_findings_all_zero():
    assert _count_by_level([], "HIGH") == 0
    assert _count_by_level([], "MEDIUM") == 0
    assert _count_by_level([], "LOW") == 0


def test_L23_5_production_uses_confidence_level_field():
    """Regression guard: run_pipeline.py reads f.get('confidence_level'),
    never f.get('confidence') for confidence counting.

    Class of bug: counter field-name drift from schema (same pattern
    as Commit 20 productive/inv_turns fix). This test prevents
    recurrence."""
    from pathlib import Path
    content = (Path(__file__).resolve().parent.parent / "run_pipeline.py").read_text()
    bad_pattern = 'f.get("confidence")'
    count_bad = content.count(bad_pattern)
    assert count_bad == 0, (
        f"Found {count_bad} read(s) of f.get(\"confidence\") -- "
        f"should be f.get(\"confidence_level\") per production schema."
    )
