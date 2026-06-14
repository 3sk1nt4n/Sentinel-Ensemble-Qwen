"""Slot 31H-alpha TASK 4 -- NO_DUPLICATE_CONFIRMED_ENTITY_HEADLINE_GATE.

A confirmed entity is headlined exactly once; duplicate finding-level
observations are folded under source_finding_ids. dataset-agnostic by
construction.
"""
from __future__ import annotations

import json

from _etp_fixture import SYN_CONFIRMED_FILE, make_synthetic_run

from sift_sentinel.entity_truth_package import (
    ENTITY_TRUTH_SUMMARY_JSON,
    ENTITY_TRUTH_SUMMARY_MD,
    NO_DUPLICATE_CONFIRMED_ENTITY_HEADLINE_GATE,
    SUBMISSION_READINESS_REPORT_MD,
    build_entity_truth_package,
)


def _build(tmp_path):
    run_json = make_synthetic_run(tmp_path)
    out = tmp_path / "pkg"
    result = build_entity_truth_package(run_json, out)
    return result, out


def test_no_duplicate_confirmed_headline_gate_passes(tmp_path):
    result, _ = _build(tmp_path)
    assert result["gates"][
        NO_DUPLICATE_CONFIRMED_ENTITY_HEADLINE_GATE] == "PASS"


def test_confirmed_entity_keys_unique_in_summary_json(tmp_path):
    _, out = _build(tmp_path)
    s = json.loads((out / ENTITY_TRUTH_SUMMARY_JSON).read_text())
    keys = [e["entity_key"] for e in s["confirmed_malicious_entities"]]
    assert keys == sorted(set(keys))
    assert len(keys) == len(set(keys))


def test_confirmed_header_appears_once_per_file_in_markdown(tmp_path):
    _, out = _build(tmp_path)
    for fname in (ENTITY_TRUTH_SUMMARY_MD, SUBMISSION_READINESS_REPORT_MD):
        md = (out / fname).read_text()
        header_token = "`file:%s`" % SYN_CONFIRMED_FILE
        assert md.count(header_token) == 1, (fname, md.count(header_token))
