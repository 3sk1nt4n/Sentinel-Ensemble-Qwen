"""Every FP/benign finding's Details cell must explain WHY it is benign --
never the generic malicious 'Why it matters' significance (which is misleading
for something the pipeline concluded is NOT malicious). Covers all benign
routing paths: ReAct verdict, FP-routing (loopback / entity propagation), and
the weak/uncorroborated floors. Universal: keyed on the pipeline's own routing
markers + reason grammar, no case data.
"""
from sift_sentinel.reporting.customer_findings_table_bucket_faithful import (
    _details_for_display,
)


def _f(**kw):
    base = {"finding_id": "F", "title": "Network listener on service",
            "description": "a service listened on a port"}
    base.update(kw)
    return base


def test_react_benign_text_is_shown():
    f = _f(react_conclusion={"is_false_positive": True,
                             "text": "legitimate antivirus agent listener"})
    d = _details_for_display(f)
    assert "Assessed benign" in d
    assert "legitimate antivirus agent" in d
    assert "Why it matters" not in d


def test_fp_routing_loopback_gets_benign_reason_not_significance():
    f = _f(final_disposition="benign_or_false_positive",
           _fp_routing_benign=True, _fp_routing_reason="loopback_only")
    d = _details_for_display(f)
    assert "Assessed benign" in d
    assert "Why it matters" not in d
    assert "loopback" in d.lower() or "localhost" in d.lower()


def test_fp_routing_entity_propagation_gets_benign_reason():
    f = _f(final_disposition="benign_or_false_positive",
           _fp_routing_benign=True,
           _fp_routing_reason="entity_benign_propagation")
    d = _details_for_display(f)
    assert "Assessed benign" in d
    assert "Why it matters" not in d


def test_uncorroborated_weak_floor_gets_benign_reason():
    f = _f(final_disposition="benign_or_false_positive",
           disposition_reasons=["gate:confirmed_ineligible[x]",
                                "benign:uncorroborated_weak_or_history_only"])
    d = _details_for_display(f)
    assert "Assessed benign" in d
    assert "Why it matters" not in d
    assert "weak" in d.lower() or "corrobor" in d.lower()


def test_non_benign_finding_still_gets_significance():
    f = _f(title="Suspicious service installation from non-standard path",
           final_disposition="suspicious_needs_review")
    d = _details_for_display(f)
    assert "Why it matters" in d
    assert "Assessed benign" not in d
