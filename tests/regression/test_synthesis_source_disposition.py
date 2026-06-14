"""Slot 31E-DB.5a-alpha TASK 5 -- SYNTHESIS_SOURCE_DISPOSITION_GATE.

A synthesis narrative may summarize confirmed items, but a referenced
non-confirmed component must render labeled by its real disposition and
must not be promoted as a standalone confirmed attack-chain fact.
Dataset-agnostic synthetic fixtures.
"""
from __future__ import annotations

from sift_sentinel.analysis.disposition import (
    BUCKET_BENIGN,
    BUCKET_CONFIRMED,
    BUCKET_SYNTHESIS,
    REQUIRED_BUCKETS,
    render_synthesis_source_components,
    synthesis_source_disposition_gate,
)


def _buckets():
    b = {name: [] for name in REQUIRED_BUCKETS}
    b[BUCKET_CONFIRMED] = [
        {"finding_id": "CONF1", "title": "staged payload execution"},
    ]
    b[BUCKET_BENIGN] = [
        {"finding_id": "BEN1", "title": "signed vendor updater"},
    ]
    b[BUCKET_SYNTHESIS] = [
        {"finding_id": "SYN1", "title": "intrusion chain",
         "source_finding_refs": ["CONF1", "BEN1"]},
    ]
    return b


def test_benign_component_labeled_and_not_promoted():
    b = _buckets()
    comps = render_synthesis_source_components(b[BUCKET_SYNTHESIS][0], b)
    by_id = {c["finding_id"]: c for c in comps}

    assert by_id["CONF1"]["promoted"] is True
    assert by_id["CONF1"]["bucket"] == BUCKET_CONFIRMED

    ben = by_id["BEN1"]
    assert ben["promoted"] is False
    assert ben["bucket"] == BUCKET_BENIGN
    assert ben["render"].startswith("benign_or_false_positive")
    assert "signed vendor updater" in ben["render"]


def test_gate_passes_when_components_labeled():
    status, violations = synthesis_source_disposition_gate(_buckets())
    assert status == "PASS"
    assert violations == []


def test_gate_flags_promoted_non_confirmed():
    # Force the labelling off by simulating a render that promotes a
    # benign component as a bare confirmed fact.
    import sift_sentinel.analysis.disposition as d

    orig = d.render_synthesis_source_components
    try:
        def _bad(syn, buckets):
            out = orig(syn, buckets)
            for c in out:
                if c["bucket"] != BUCKET_CONFIRMED:
                    c["promoted"] = True
                    c["render"] = c["title"]
            return out

        d.render_synthesis_source_components = _bad
        status, violations = d.synthesis_source_disposition_gate(_buckets())
        assert status == "FAIL"
        assert any("promoted_non_confirmed" in v for v in violations)
    finally:
        d.render_synthesis_source_components = orig


def test_marker():
    print("SYNTHESIS_SOURCE_DISPOSITION_GATE=PASS")
    assert True
