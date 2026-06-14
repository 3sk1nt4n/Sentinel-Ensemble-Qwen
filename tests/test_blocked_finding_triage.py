"""Triage for SC-blocked findings: cheapest-first routing that eliminates the
UNRESOLVED limbo and spends a new ReAct call only when nothing free decides it.
Universal: asserts the ROUTING POLICY, never a case value.
"""
from sift_sentinel.analysis.blocked_finding_triage import (
    triage_route, ROUTE_BENIGN, ROUTE_NEEDS_REVIEW, ROUTE_REACT,
)


def test_reuses_existing_react_verdict_for_free():
    assert triage_route("confirmed_benign")[0] == ROUTE_BENIGN
    assert triage_route("confirmed_malicious")[0] == ROUTE_NEEDS_REVIEW
    assert triage_route("inconclusive")[0] == ROUTE_NEEDS_REVIEW


def test_structural_signal_decides_when_no_verdict():
    assert triage_route(None, has_malice_signal=True)[0] == ROUTE_NEEDS_REVIEW
    assert triage_route(None, has_benign_signal=True)[0] == ROUTE_BENIGN


def test_only_genuinely_ambiguous_spends_a_react_call():
    # nothing free decides it -> the single new-cost path
    assert triage_route(None)[0] == ROUTE_REACT
    # conflicting structural signals -> also defer to ReAct, never guess
    assert triage_route("", has_malice_signal=True, has_benign_signal=True)[0] == ROUTE_REACT


def test_existing_verdict_beats_structural_signal():
    # the free verdict wins -> never re-investigate what ReAct already judged
    assert triage_route("confirmed_benign", has_malice_signal=True)[0] == ROUTE_BENIGN
    assert triage_route("confirmed_malicious", has_benign_signal=True)[0] == ROUTE_NEEDS_REVIEW


def test_reason_is_carried_for_audit():
    assert triage_route("confirmed_benign")[1] == "react:confirmed_benign"
    assert triage_route(None, has_malice_signal=True)[1] == "structural_malice"
    assert triage_route(None)[1] == "ambiguous_needs_react"
