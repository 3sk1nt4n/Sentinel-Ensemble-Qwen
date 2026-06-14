"""Exec-summary / confirmed-bucket consistency: the report's prose may never
label a finding 'confirmed' when the disposition bucket says otherwise.

Live defect SHAPE (tokens genericized -- repo stays case-neutral): Inv4
free-wrote 'Confirmed malicious activity: F034, F009, F016' while the
deterministic confirmed bucket held {F034, F025, F009} -- F016 was
needs-review. A judge reading headline then structured section sees a direct
contradiction. validate_report only checked that cited IDs EXIST.

reconcile_confirmed_mentions appends the finding's TRUE bucket after any
F-id named on a positive confirm-context line when that id is not in the
confirmed bucket. Deterministic, additive (never rewrites model prose),
idempotent, fail-safe, kill-switch SIFT_CONFIRMED_CONSISTENCY=0. Universal:
keyed on bucket membership + the word-stem 'confirm', no case data.
"""
import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
)

from sift_sentinel.analysis.confirmed_consistency import (  # noqa: E402
    reconcile_confirmed_mentions,
    scan_confirmed_contradictions,
)


def _buckets():
    return {
        "confirmed_malicious_atomic": [
            {"finding_id": "F034"}, {"finding_id": "F025"}, {"finding_id": "F009"},
        ],
        "suspicious_needs_review": [{"finding_id": "F016"}, {"finding_id": "F039"}],
        "benign_or_false_positive": [{"finding_id": "F005"}],
        "inconclusive_unresolved": [{"finding_id": "F011"}],
        "synthesis_narrative": [{"finding_id": "F060"}],
    }


def test_non_confirmed_id_in_confirm_context_gets_true_bucket_annotation():
    md = "## Executive Summary\nConfirmed malicious activity: F034, F009, F016."
    out, n = reconcile_confirmed_mentions(md, _buckets())
    assert n == 1
    assert "F016 (status: needs review -- NOT in the confirmed set)" in out
    # confirmed ids untouched
    assert "F034," in out and "F009," in out
    assert "F034 (status" not in out and "F009 (status" not in out


def test_benign_and_inconclusive_ids_annotated_with_their_bucket():
    md = "The investigation confirmed F005 and F011 as malicious."
    out, n = reconcile_confirmed_mentions(md, _buckets())
    assert n == 2
    assert "F005 (status: benign/false positive -- NOT in the confirmed set)" in out
    assert "F011 (status: inconclusive -- NOT in the confirmed set)" in out


def test_phantom_id_annotated_as_unrecognized():
    md = "Confirmed findings: F034, F099."
    out, n = reconcile_confirmed_mentions(md, _buckets())
    assert n == 1
    assert "F099 (status: not a finding id from this run)" in out


def test_line_without_confirm_stem_is_never_touched():
    md = "Suspicious activity worth review: F016, F039 and F005."
    out, n = reconcile_confirmed_mentions(md, _buckets())
    assert n == 0
    assert out == md


def test_confirmed_benign_idiom_is_not_a_malicious_confirm_context():
    # 'confirmed benign' / 'confirmed as a false positive' assert the BENIGN
    # verdict -- annotating would be a false contradiction.
    md = "AI cross-check confirmed F005 benign.\nF039 was confirmed as a false positive."
    out, n = reconcile_confirmed_mentions(md, _buckets())
    assert n == 0
    assert out == md


def test_negated_confirm_context_is_skipped():
    md = "F016 could not be confirmed.\nF039 remains unconfirmed."
    out, n = reconcile_confirmed_mentions(md, _buckets())
    assert n == 0
    assert out == md


def test_idempotent_second_pass_adds_nothing():
    md = "Confirmed: F034, F016."
    once, n1 = reconcile_confirmed_mentions(md, _buckets())
    twice, n2 = reconcile_confirmed_mentions(once, _buckets())
    assert n1 == 1 and n2 == 0
    assert twice == once


def test_hyphenated_id_shape_also_reconciled():
    md = "Confirmed malicious: F-016."
    out, n = reconcile_confirmed_mentions(md, _buckets())
    assert n == 1
    assert "F-016 (status: needs review -- NOT in the confirmed set)" in out


def test_kill_switch(monkeypatch):
    monkeypatch.setenv("SIFT_CONFIRMED_CONSISTENCY", "0")
    md = "Confirmed: F016."
    out, n = reconcile_confirmed_mentions(md, _buckets())
    assert n == 0 and out == md


def test_fail_safe_on_garbage():
    out, n = reconcile_confirmed_mentions(None, _buckets())
    assert n == 0
    out2, n2 = reconcile_confirmed_mentions("Confirmed: F016.", None)
    assert n2 == 0 and out2 == "Confirmed: F016."


def test_scan_reports_contradictions_without_rewriting():
    md = "Confirmed malicious activity: F034, F016."
    hits = scan_confirmed_contradictions(md, {"F034", "F025", "F009"})
    assert [h["finding_id"] for h in hits] == ["F016"]


def test_validate_report_warns_on_confirm_context_contradiction():
    from sift_sentinel.validation.report_validation import validate_report
    payload = {
        "report": "Confirmed malicious activity: F034, F016.",
        "findings": [
            {"finding_id": "F034", "tool_call_ids": ["t1"], "raw_excerpt": "x"},
        ],
    }
    dispositioned = [
        {"finding_id": "F034", "tool_call_ids": ["t1"], "raw_excerpt": "x"},
        {"finding_id": "F016", "tool_call_ids": ["t2"], "raw_excerpt": "y"},
    ]
    res = validate_report(payload, dispositioned)
    # contradiction is telemetry (warning), never a banner-triggering error
    assert any("F016" in w and "confirm" in w.lower() for w in res["warnings"])
    assert all("F016" not in e for e in res["errors"])
