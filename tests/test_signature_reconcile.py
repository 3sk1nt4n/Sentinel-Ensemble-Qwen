"""Verdict-consistency reconciliation (lever 2 / C1). Identical-signature findings
get one disposition; the rule never auto-confirms and never demotes a validated
confirm. Universal: signature is computed from title shape, never a case literal."""
from sift_sentinel.analysis.signature_reconcile import (
    finding_signature,
    reconcile_dispositions,
    CONFIRMED, NEEDS_REVIEW, INCONCLUSIVE, BENIGN,
)


def _f(fid, title):
    return {"finding_id": fid, "title": title}


def test_signature_is_pid_invariant():
    a = finding_signature(_f("F1", "Multiple rundll32.exe instances with null command lines (PID 2216)"))
    b = finding_signature(_f("F2", "Multiple rundll32.exe instances with null command lines (PID 5452)"))
    assert a == b and a != ""


def test_signature_empty_for_trivial_titles():
    assert finding_signature(_f("F1", "x")) == ""
    assert finding_signature({"finding_id": "F1"}) == ""


def test_contradicted_group_is_made_consistent_toward_review():
    # 6 rundll32 in review + 1 in benign -> all 7 land in needs-review (most cautious)
    title = "Multiple rundll32.exe instances with null command lines"
    buckets = {
        CONFIRMED: [],
        NEEDS_REVIEW: [_f("F9", title), _f("F11", title), _f("F12", title)],
        INCONCLUSIVE: [],
        BENIGN: [_f("F10", title)],
        "synthesis_narrative": [],
    }
    new, ledger = reconcile_dispositions(buckets)
    review_ids = {x["finding_id"] for x in new[NEEDS_REVIEW]}
    assert review_ids == {"F9", "F11", "F12", "F10"}
    assert new[BENIGN] == []
    assert any(m["finding_id"] == "F10" and m["to"] == NEEDS_REVIEW for m in ledger)


def test_never_auto_confirms_or_demotes_confirmed():
    title = "credential dumping tool staged in temp directory"
    buckets = {
        CONFIRMED: [_f("F24", title)],
        NEEDS_REVIEW: [],
        INCONCLUSIVE: [],
        BENIGN: [_f("F30", title)],
        "synthesis_narrative": [],
    }
    new, ledger = reconcile_dispositions(buckets)
    # the confirmed finding stays confirmed; the benign sibling is NOT pulled into confirmed
    assert {x["finding_id"] for x in new[CONFIRMED]} == {"F24"}
    assert "F30" not in {x["finding_id"] for x in new[CONFIRMED]}
    # F30 moves to the most-cautious NON-confirmed bucket present (needs-review default)
    assert "F30" in {x["finding_id"] for x in new[NEEDS_REVIEW]}


def test_consistent_group_is_untouched():
    title = "Multiple rundll32.exe instances with null command lines"
    buckets = {
        CONFIRMED: [], NEEDS_REVIEW: [_f("F9", title), _f("F11", title)],
        INCONCLUSIVE: [], BENIGN: [], "synthesis_narrative": [],
    }
    new, ledger = reconcile_dispositions(buckets)
    assert ledger == []
    assert {x["finding_id"] for x in new[NEEDS_REVIEW]} == {"F9", "F11"}


def test_distinct_findings_are_not_grouped():
    buckets = {
        CONFIRMED: [], NEEDS_REVIEW: [_f("F1", "lsass credential access via handle")],
        INCONCLUSIVE: [], BENIGN: [_f("F2", "scheduled task points to staging path")],
        "synthesis_narrative": [],
    }
    new, ledger = reconcile_dispositions(buckets)
    assert ledger == []  # different signatures -> no move
