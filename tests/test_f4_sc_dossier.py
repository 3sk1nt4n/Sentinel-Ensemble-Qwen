"""F4 self-correction rich-context dossier regression tests.

Covers the Python-side dossier that organizes bounded evidence context
for SC attempts. The AI remains detector and resolver; the dossier is
read-only scaffolding.
"""

from __future__ import annotations

import logging

import pytest

from sift_sentinel.correction.self_correct import (
    build_sc_context_dossier,
    _f4_sample_records,
    _f4_render_dossier_for_prompt,
    _f4_log_decision,
    _F4_ALLOWED_ACTIONS,
    _F4_MAX_DOSSIER_BYTES,
    _F4_MAX_TOOLS_IN_DOSSIER,
)
from sift_sentinel.correction.strategies import STRATEGIES


# ── Dossier shape ────────────────────────────────────────────────────────

def test_dossier_has_required_keys():
    d = build_sc_context_dossier({"finding_id": "X"}, "err", None, {}, {})
    for key in (
        "finding_id",
        "validator_error",
        "failed_claim_summary",
        "subject_index",
        "matches",
        "sample_records",
        "allowed_actions",
        "size_bytes",
    ):
        assert key in d, f"missing key: {key}"


def test_matches_has_expected_subkeys():
    d = build_sc_context_dossier({"finding_id": "X"}, "err", None, {}, {})
    matches = d["matches"]
    for key in ("exact", "conflicting", "near", "missing_from_tools"):
        assert key in matches, f"missing matches subkey: {key}"
        assert isinstance(matches[key], list)


# ── Conflict detection ───────────────────────────────────────────────────

def test_hash_wrong_filename_conflict_detected():
    h = "a" * 40
    finding = {
        "finding_id": "H1",
        "claims": [{"type": "hash", "sha1": h, "filename": "wrong.exe"}],
    }
    ref = {"hashes": {h: "right.exe"}}
    d = build_sc_context_dossier(finding, "err", None, {}, ref)

    assert d["matches"]["conflicting"], "hash->filename conflict not detected"
    conflict_text = d["matches"]["conflicting"][0]
    assert "wrong.exe" in conflict_text
    assert "right.exe" in conflict_text


def test_pid_wrong_process_conflict_detected():
    finding = {
        "finding_id": "P1",
        "claims": [{"type": "pid", "pid": 1234, "process": "evil.exe"}],
    }
    ref = {"pids": {"1234": "svchost.exe"}}
    d = build_sc_context_dossier(finding, "err", None, {}, ref)

    assert d["matches"]["conflicting"], "pid->process conflict not detected"
    conflict_text = d["matches"]["conflicting"][0]
    assert "evil.exe" in conflict_text
    assert "svchost.exe" in conflict_text


def test_no_conflict_when_pid_process_match():
    finding = {
        "finding_id": "OK",
        "claims": [{"type": "pid", "pid": 1234, "process": "svchost.exe"}],
    }
    ref = {"pids": {"1234": "svchost.exe"}}
    d = build_sc_context_dossier(finding, "err", None, {}, ref)

    assert d["matches"]["conflicting"] == [], "false positive conflict raised"


# ── Record sampling and prioritization ───────────────────────────────────

def test_matching_records_prioritized_over_earlier_non_matching():
    """Records containing subject tokens must appear BEFORE earlier
    non-matching records in the combined sample, even though in the
    source list the matching record appears last."""
    finding = {
        "finding_id": "PRIO",
        "claims": [{"type": "pid", "pid": 99999, "process": "evil.exe"}],
    }
    raw_data = {
        "vol_pstree": {
            "records": (
                [{"pid": i, "data": f"benign_{i}"} for i in range(15)]
                + [{"pid": 99999, "data": "target_record"}]
            )
        }
    }
    d = build_sc_context_dossier(finding, "err", None, raw_data, {})
    sampled = d["sample_records"].get("vol_pstree", [])

    assert sampled, "no records sampled from vol_pstree"
    assert "99999" in str(sampled[0]), (
        f"expected late matching record to be first, got: {sampled[0]!r}"
    )


def test_f4_sample_records_returns_empty_for_non_dict():
    assert _f4_sample_records(None, {"pids": []}) == {}
    assert _f4_sample_records("not a dict", {"pids": []}) == {}


# ── Hard 6KB budget ──────────────────────────────────────────────────────

def test_budget_enforced_with_huge_raw_data():
    big_record = {"data": "x" * 1200}
    raw_data = {
        f"tool_{i}": {
            "records": [dict(big_record) for _ in range(10)],
        }
        for i in range(8)
    }
    finding = {
        "finding_id": "HUGE",
        "claims": [{"type": "pid", "pid": 123, "process": "evil.exe"}],
    }
    d = build_sc_context_dossier(finding, "err", None, raw_data, {})

    assert d["size_bytes"] <= _F4_MAX_DOSSIER_BYTES, (
        f"dossier exceeded 6KB cap: {d['size_bytes']}B"
    )


def test_budget_enforced_with_huge_validator_error():
    finding = {"finding_id": "BIGERR", "claims": [{"pid": 1}]}
    d = build_sc_context_dossier(finding, "x" * 20000, None, {}, {})

    assert d["size_bytes"] <= _F4_MAX_DOSSIER_BYTES


def test_sample_records_capped_at_max_tools():
    raw_data = {
        f"tool_{i}": {
            "records": [{"data": f"rec_{j}"} for j in range(3)],
        }
        for i in range(10)
    }
    finding = {"finding_id": "CAP", "claims": [{"pid": 1}]}
    d = build_sc_context_dossier(finding, "err", None, raw_data, {})

    assert len(d["sample_records"]) <= _F4_MAX_TOOLS_IN_DOSSIER


# ── Allowed actions ──────────────────────────────────────────────────────

def test_all_four_allowed_actions_exported():
    assert len(_F4_ALLOWED_ACTIONS) == 4
    assert "rewrite_with_verified_claims" in _F4_ALLOWED_ACTIONS
    assert "downgrade_to_inference" in _F4_ALLOWED_ACTIONS
    assert "split_claim" in _F4_ALLOWED_ACTIONS
    assert "drop_finding" in _F4_ALLOWED_ACTIONS


def test_dossier_includes_allowed_actions():
    d = build_sc_context_dossier({"finding_id": "X"}, "err", None, {}, {})
    assert "allowed_actions" in d
    actions = d["allowed_actions"]
    assert isinstance(actions, list)
    assert "drop_finding" in actions
    assert "rewrite_with_verified_claims" in actions


# ── Strategy template integration ────────────────────────────────────────

def test_all_strategies_have_context_dossier_placeholder():
    for k, strategy in STRATEGIES.items():
        assert "{context_dossier}" in strategy["template"], (
            f"strategy {k} missing {{context_dossier}}"
        )


def test_strategy_templates_mention_drop_finding():
    for k, strategy in STRATEGIES.items():
        assert "drop_finding" in strategy["template"], (
            f"strategy {k} missing drop_finding language"
        )


def test_honest_drop_language_present():
    combined = "\n".join(s["template"].lower() for s in STRATEGIES.values())
    assert (
        "honest inconclusive" in combined
        or "valid self-correction" in combined
        or "unsupported claim" in combined
    ), "no honest-drop language in strategy templates"


# ── Decision logging ─────────────────────────────────────────────────────

def test_log_decision_handles_action_drop(caplog):
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="sift_sentinel.correction.self_correct"):
        _f4_log_decision("F_DROP", 1, {"action": "drop"}, "err")

    assert "INCONCLUSIVE" in caplog.text
    assert "F_DROP" in caplog.text


def test_log_decision_handles_action_drop_finding(caplog):
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="sift_sentinel.correction.self_correct"):
        _f4_log_decision("F_DROP2", 2, {"action": "drop_finding"}, "err")

    assert "INCONCLUSIVE" in caplog.text
    assert "F_DROP2" in caplog.text


# ── Defensive behavior ──────────────────────────────────────────────────

def test_empty_finding_does_not_crash():
    d = build_sc_context_dossier({}, "err", None, {}, {})
    assert isinstance(d, dict)
    assert d["finding_id"] == "?"


def test_none_raw_data_and_ref_set_do_not_crash():
    d = build_sc_context_dossier(
        {"finding_id": "X"}, "err", None, None, None,
    )
    assert isinstance(d, dict)
    assert d["matches"]["conflicting"] == []


# ── Rendered prompt text ────────────────────────────────────────────────

def test_render_includes_section_headers():
    d = build_sc_context_dossier({"finding_id": "RENDER"}, "err", None, {}, {})
    text = _f4_render_dossier_for_prompt(d)
    assert "SUBJECT INDEX" in text
    assert "MATCHES" in text
    assert "ALLOWED ACTIONS" in text


def test_rendered_prompt_includes_finding_id():
    d = build_sc_context_dossier(
        {"finding_id": "TEST-F123"}, "err", None, {}, {},
    )
    text = _f4_render_dossier_for_prompt(d)
    assert "TEST-F123" in text
