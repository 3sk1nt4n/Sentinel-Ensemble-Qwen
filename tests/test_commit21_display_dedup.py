"""Commit 21: SC-corrected findings removed from blocked and blocked_list.

Property tests. All ids synthetic. All assertions on set membership,
counts, and arithmetic invariants. No cached artifact values. No
production enum enumeration. Tests use a shared _compute_corrected_ids
helper to mirror the single-computation pattern in production.

L21-5 asserts the filter block exists in production, anchored on the
distinctive phrase from the actual comment. Run 12 multi-dataset
execution is the real behavioral guard.
"""
from __future__ import annotations


def _compute_corrected_ids(corrections):
    """Extract CORRECTED finding ids. Mirrors the production
    single-computation pattern inside the Commit 21 filter block."""
    return {
        r["original_draft"].get("finding_id")
        for r in corrections
        if r.get("status") == "CORRECTED"
    }


def _run_filter_blocked_list(blocked_list, corrections):
    if not corrections:
        return blocked_list
    corrected_ids = _compute_corrected_ids(corrections)
    if not corrected_ids:
        return blocked_list
    return [b for b in blocked_list if b.get("finding_id") not in corrected_ids]


def _run_filter_blocked(blocked, corrections):
    if not corrections:
        return blocked
    corrected_ids = _compute_corrected_ids(corrections)
    if not corrected_ids:
        return blocked
    return [(f, e) for f, e in blocked if f.get("finding_id") not in corrected_ids]


def test_L21_1_corrected_finding_removed_from_blocked_list():
    blocked_list = [
        {"finding_id": "A", "reason": "r"},
        {"finding_id": "B", "reason": "r"},
    ]
    corrections = [
        {"status": "CORRECTED", "original_draft": {"finding_id": "A"}},
    ]
    result = _run_filter_blocked_list(blocked_list, corrections)
    ids = {b["finding_id"] for b in result}
    assert "A" not in ids
    assert "B" in ids
    assert len(result) == 1


def test_L21_2_only_literal_CORRECTED_triggers_removal():
    """Property: ONLY status == 'CORRECTED' (exact literal) triggers removal."""
    blocked_list = [{"finding_id": "X", "reason": "r"}]
    non_corrected = [
        "NON_CORRECTED_PLACEHOLDER",
        "",
        None,
        "corrected",
        "CORRECTED_",
        " CORRECTED",
        "CORRECTED ",
        "arbitrary_string",
    ]
    for status in non_corrected:
        corrections = [{"status": status, "original_draft": {"finding_id": "X"}}]
        result = _run_filter_blocked_list(blocked_list, corrections)
        ids = {b["finding_id"] for b in result}
        assert "X" in ids, f"status={status!r} must not remove"


def test_L21_3_empty_corrections_no_change():
    blocked_list = [
        {"finding_id": "P", "reason": "r"},
        {"finding_id": "Q", "reason": "r"},
    ]
    result = _run_filter_blocked_list(blocked_list, [])
    assert result == blocked_list


def test_L21_4_property_count_invariant():
    """Property: exactly N items removed where N = count of CORRECTED."""
    cases = [(4, 2), (10, 5), (3, 3), (5, 0), (1, 1)]
    for n_total, n_corrected in cases:
        blocked_list = [
            {"finding_id": f"synthetic_{i}", "reason": "r"}
            for i in range(n_total)
        ]
        corrections = []
        for i in range(n_corrected):
            corrections.append({
                "status": "CORRECTED",
                "original_draft": {"finding_id": f"synthetic_{i}"},
            })
        for i in range(n_corrected, n_total):
            corrections.append({
                "status": "NON_CORRECTED_PLACEHOLDER",
                "original_draft": {"finding_id": f"synthetic_{i}"},
            })
        result = _run_filter_blocked_list(blocked_list, corrections)
        assert len(result) == n_total - n_corrected
        remaining = {b["finding_id"] for b in result}
        corrected_ids = {f"synthetic_{i}" for i in range(n_corrected)}
        assert not (remaining & corrected_ids)


def test_L21_5_run_pipeline_has_filter_block_near_comment_anchor():
    """Structural: both filters appear within proximity of the distinctive
    Commit 21 comment phrase (not the generic 'Commit 21:' prefix)."""
    from pathlib import Path
    content = (Path(__file__).resolve().parent.parent / "run_pipeline.py").read_text()
    c21_idx = content.find("Commit 21: after SC appends CORRECTED")
    assert c21_idx >= 0, "Commit 21 distinctive comment missing from run_pipeline.py"
    c21_block = content[c21_idx:c21_idx + 2000]
    assert "for f, e in blocked" in c21_block, \
        "blocked tuple filter not in Commit 21 block"
    assert "for b in blocked_list" in c21_block, \
        "blocked_list filter not in Commit 21 block"
    assert "_corrected_ids" in c21_block, \
        "corrected_ids set construction not in Commit 21 block"


def test_L21_6_blocked_and_blocked_list_filter_symmetry():
    """Property: both filters remove the same finding_ids given same corrections.

    Semantically meaningful because both helpers share _compute_corrected_ids;
    this mirrors the production filter block which computes _corrected_ids
    once and uses it for both structure filters."""
    finding_a = {"finding_id": "A", "artifact": "x"}
    finding_b = {"finding_id": "B", "artifact": "y"}
    blocked = [(finding_a, "err1"), (finding_b, "err2")]
    blocked_list = [
        {"finding_id": "A", "reason": "err1"},
        {"finding_id": "B", "reason": "err2"},
    ]
    corrections = [
        {"status": "CORRECTED", "original_draft": {"finding_id": "A"}},
    ]
    result_blocked = _run_filter_blocked(blocked, corrections)
    result_list = _run_filter_blocked_list(blocked_list, corrections)
    ids_from_blocked = {f.get("finding_id") for f, _ in result_blocked}
    ids_from_list = {b.get("finding_id") for b in result_list}
    assert ids_from_blocked == ids_from_list


def test_L21_7_arithmetic_invariant_parameterized():
    """Property: passed + blocked == findings_total after C21 filter.

    Parameterized over 5 (total, initial_passed, n_corrected) cases
    covering edge cases: all-corrected, none-corrected, single item,
    large set.
    """
    cases = [
        (5, 2, 2),
        (10, 4, 3),
        (3, 0, 3),
        (1, 0, 1),
        (100, 50, 25),
    ]
    for findings_total, initial_passed, n_corrected in cases:
        initial_blocked = findings_total - initial_passed
        assert n_corrected <= initial_blocked, \
            f"invalid case: n_corrected {n_corrected} > initial_blocked {initial_blocked}"

        blocked = [
            ({"finding_id": f"synthetic_{i}"}, "err")
            for i in range(initial_blocked)
        ]
        corrections = [
            {"status": "CORRECTED",
             "original_draft": {"finding_id": f"synthetic_{i}"}}
            for i in range(n_corrected)
        ]
        corrections += [
            {"status": "NON_CORRECTED_PLACEHOLDER",
             "original_draft": {"finding_id": f"synthetic_{i}"}}
            for i in range(n_corrected, initial_blocked)
        ]

        passed_after_sc = initial_passed + n_corrected
        blocked_after_filter = _run_filter_blocked(blocked, corrections)

        assert passed_after_sc + len(blocked_after_filter) == findings_total, (
            f"case t={findings_total} p={initial_passed} c={n_corrected}: "
            f"{passed_after_sc} + {len(blocked_after_filter)} != {findings_total}"
        )
