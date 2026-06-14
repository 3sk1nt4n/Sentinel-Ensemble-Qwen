"""Adversarial + universality regression guards for the inv3a finalization pass.

These pin the SAFETY contract against a HOSTILE adjudicator (the AI cannot be
trusted to be well-behaved) and prove the pass is dataset-agnostic. Distinct from
test_inv3a_finalize.py (happy-path contract) — here every input is chosen to try
to BREAK fail-closed behaviour or smuggle in case assumptions.
"""
import copy
import json
import re

import pytest

from sift_sentinel.analysis.inv3a_finalize import (
    build_inv3a_prompt,
    finalize_dispositions,
    parse_inv3a_verdicts,
    select_ambiguous,
)


def _buckets():
    return {
        "confirmed_malicious_atomic": [{"finding_id": "C1", "description": "kernel callback hook"}],
        "suspicious_needs_review": [
            {"finding_id": "S1", "description": "a"},
            {"finding_id": "S2", "description": "b"},
        ],
        "benign_or_false_positive": [{"finding_id": "B1", "description": "signed"}],
        "inconclusive_unresolved": [{"finding_id": "I1", "description": "thin"}],
        "synthesis_narrative": [{"finding_id": "N1"}],
    }


def _const(text):
    return lambda _prompt: text


# ── A. FAIL-CLOSED under a hostile adjudicator ────────────────────────────────
def test_hostile_confirm_everything_promotes_nothing_without_eligibility():
    adj = _const(json.dumps({"verdicts": [
        {"finding_id": fid, "disposition": "confirmed", "reason": "trust me"}
        for fid in ("S1", "S2", "I1")]}))
    new, _ = finalize_dispositions(_buckets(), adj)  # no eligibility_fn
    assert {f["finding_id"] for f in new["confirmed_malicious_atomic"]} == {"C1"}
    assert {"S1", "S2", "I1"} <= {f["finding_id"] for f in new["suspicious_needs_review"]}


def test_cannot_touch_confirmed_or_benign_buckets():
    adj = _const(json.dumps({"verdicts": [
        {"finding_id": "C1", "disposition": "false_positive", "reason": "x"},
        {"finding_id": "B1", "disposition": "confirmed", "reason": "x"}]}))
    new, ledger = finalize_dispositions(_buckets(), adj, eligibility_fn=lambda f: True)
    assert {f["finding_id"] for f in new["confirmed_malicious_atomic"]} == {"C1"}
    assert {f["finding_id"] for f in new["benign_or_false_positive"]} == {"B1"}
    assert ledger == []


@pytest.mark.parametrize("bad", [
    '{"verdicts":[{"finding_id":"S1","dispo',   # truncated
    "```json\n{broken",                         # fence + garbage
    "",                                          # empty
    "null",                                      # json null
    "[1,2,3]",                                   # array of scalars
    "{}",                                        # empty object
    "not json at all",                           # prose
])
def test_malformed_adjudicator_output_is_a_noop(bad):
    new, ledger = finalize_dispositions(_buckets(), _const(bad))
    assert ledger == []
    assert {f["finding_id"] for f in new["suspicious_needs_review"]} == {"S1", "S2"}


def test_verdict_for_nonexistent_id_is_ignored():
    adj = _const(json.dumps({"verdicts": [
        {"finding_id": "GHOST", "disposition": "confirmed", "reason": "x"}]}))
    new, ledger = finalize_dispositions(_buckets(), adj, eligibility_fn=lambda f: True)
    all_ids = [f.get("finding_id") for v in new.values() for f in v]
    assert "GHOST" not in all_ids and ledger == []


def test_adjudicator_exception_is_fail_closed():
    def boom(_prompt):
        raise RuntimeError("api down")
    new, ledger = finalize_dispositions(_buckets(), boom)
    assert ledger == []
    assert {f["finding_id"] for f in new["suspicious_needs_review"]} == {"S1", "S2"}


def test_non_dict_items_and_null_fields_are_robust():
    adj = _const(json.dumps({"verdicts": [
        None, 42, "str",
        {"finding_id": "S1", "disposition": "false_positive", "reason": None}]}))
    new, ledger = finalize_dispositions(_buckets(), adj)
    assert "S1" in {f["finding_id"] for f in new["benign_or_false_positive"]}
    assert len(ledger) == 1


# ── B. Universal / dataset-agnostic ───────────────────────────────────────────
def test_non_windows_findings_adjudicate_structurally():
    lin = {
        "confirmed_malicious_atomic": [], "benign_or_false_positive": [],
        "synthesis_narrative": [],
        "suspicious_needs_review": [
            {"finding_id": "L1", "description": "/etc/cron.d reverse shell", "source_tools": ["auditd"]}],
        "inconclusive_unresolved": [
            {"finding_id": "L2", "description": "launchd plist anomaly", "source_tools": ["fsevents"]}],
    }
    adj = _const(json.dumps({"verdicts": [
        {"finding_id": "L1", "disposition": "confirmed", "reason": "persistence"},
        {"finding_id": "L2", "disposition": "false_positive", "reason": "benign"}]}))
    new, _ = finalize_dispositions(lin, adj, eligibility_fn=lambda f: f["finding_id"] == "L1")
    assert "L1" in {f["finding_id"] for f in new["confirmed_malicious_atomic"]}
    assert "L2" in {f["finding_id"] for f in new["benign_or_false_positive"]}


def test_unicode_and_odd_finding_ids():
    weird = {
        "confirmed_malicious_atomic": [], "benign_or_false_positive": [],
        "synthesis_narrative": [],
        "suspicious_needs_review": [
            {"finding_id": "找-001", "description": "日本語 evidence"},
            {"finding_id": "f/2#@"}],
        "inconclusive_unresolved": [{"finding_id": "X", "description": ""}],
    }
    pr = build_inv3a_prompt(select_ambiguous(weird))
    assert "找-001" in pr and "f/2#@" in pr
    adj = _const(json.dumps({"verdicts": [
        {"finding_id": "找-001", "disposition": "false_positive", "reason": "u"}]}))
    new, _ = finalize_dispositions(weird, adj)
    assert "找-001" in {f["finding_id"] for f in new["benign_or_false_positive"]}


def test_prompt_embeds_no_ioc_shape_of_its_own():
    pr = build_inv3a_prompt(select_ambiguous(_buckets()))
    assert not re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", pr)   # no IPv4
    assert not re.search(r"\b[a-fA-F0-9]{32,}\b", pr)          # no hash
    assert ".onion" not in pr.lower()


# ── C. _live_call return-shape bridge (the real wiring path) ──────────────────
def _bridge(live_ret):
    if live_ret is None:
        return ""
    if isinstance(live_ret, str):
        return live_ret
    try:
        return json.dumps(live_ret)
    except Exception:
        return str(live_ret)


@pytest.mark.parametrize("live_ret,expect", [
    ({"verdicts": [{"finding_id": "S1", "disposition": "false_positive", "reason": "x"}]}, "false_positive"),
    ([{"finding_id": "S1", "disposition": "false_positive", "reason": "x"}], "false_positive"),
    (None, None),
])
def test_live_call_bridge_shapes(live_ret, expect):
    out = parse_inv3a_verdicts(_bridge(live_ret))
    if expect is None:
        assert out == {}
    else:
        assert out["S1"]["disposition"] == expect


# ── D. Purity ─────────────────────────────────────────────────────────────────
def test_input_buckets_never_mutated():
    src = _buckets()
    snap = copy.deepcopy(src)
    finalize_dispositions(src, _const(json.dumps(
        {"verdicts": [{"finding_id": "S1", "disposition": "false_positive", "reason": "x"}]})))
    assert src == snap
