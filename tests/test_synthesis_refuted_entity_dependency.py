from copy import deepcopy
from pathlib import Path

from sift_sentinel.analysis.entity_reconcile import (
    find_synthesis_refuted_entity_demotions,
)


def _finding(fid, title="Generic synthesis", **extra):
    f = {
        "finding_id": fid,
        "title": title,
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "claims": [{"type": "pid", "pid": 100, "process": "generic.exe"}],
    }
    f.update(extra)
    return f


def test_synthesis_with_refuted_entity_is_recommended_for_review():
    buckets = {
        "synthesis_narrative": [_finding("F100", "Attack chain synthesis")],
        "benign_or_false_positive": [_finding("F010", "Refuted component")],
    }
    context = {
        "F100": {
            "entity_react_refuted_by": ["F010"],
            "entity_react_confirmed_by": [],
        }
    }

    audit = find_synthesis_refuted_entity_demotions(buckets, context)

    assert audit["moved_finding_ids"] == ["F100"]
    row = audit["per_finding"][0]
    assert row["reason"] == "synthesis_depends_on_refuted_entity"
    assert row["recommended_action"] == "demote_to_review_and_cap_severity"


def test_synthesis_without_refuted_entity_is_preserved():
    buckets = {
        "synthesis_narrative": [_finding("F200", "Clean synthesis")],
    }
    context = {
        "F200": {
            "entity_react_refuted_by": [],
            "entity_react_confirmed_by": ["F201"],
        }
    }

    audit = find_synthesis_refuted_entity_demotions(buckets, context)

    assert audit["moved_finding_ids"] == []
    assert audit["preserved_finding_ids"] == ["F200"]


def test_non_synthesis_finding_is_not_demoted_by_this_helper():
    buckets = {
        "confirmed_malicious_atomic": [_finding("F300", "Atomic process fact")],
    }
    context = {
        "F300": {
            "entity_react_refuted_by": ["F301"],
            "entity_react_confirmed_by": [],
        }
    }

    audit = find_synthesis_refuted_entity_demotions(buckets, context)

    assert audit["moved_finding_ids"] == []


def test_explicit_split_justification_preserves_for_future_independent_anchor():
    buckets = {
        "synthesis_narrative": [
            _finding(
                "F400",
                "Split-justified synthesis",
                independent_confirmed_anchor=True,
            )
        ],
    }
    context = {
        "F400": {
            "entity_react_refuted_by": ["F401"],
            "entity_react_confirmed_by": ["F402"],
        }
    }

    audit = find_synthesis_refuted_entity_demotions(buckets, context)

    assert audit["moved_finding_ids"] == []
    assert audit["preserved_finding_ids"] == ["F400"]
    assert audit["per_finding"][0]["reason"] == (
        "explicit_independent_anchor_or_split_justification"
    )


def test_helper_does_not_mutate_inputs():
    buckets = {
        "synthesis_narrative": [_finding("F500", "Mutation check")],
    }
    context = {
        "F500": {
            "entity_react_refuted_by": ["F501"],
            "entity_react_confirmed_by": [],
        }
    }
    before = deepcopy(buckets)

    find_synthesis_refuted_entity_demotions(buckets, context)

    assert buckets == before


def test_run_pipeline_has_synthesis_refuted_dependency_hook():
    text = Path("run_pipeline.py").read_text(errors="replace")
    assert "SYNTHESIS_REFUTED_ENTITY_DEPENDENCY_GATE" in text
    assert "find_synthesis_refuted_entity_demotions" in text
    assert "synthesis_depends_on_refuted_entity_demoted_to_review" in text
