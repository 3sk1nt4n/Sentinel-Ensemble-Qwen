"""Slot 31H-alpha TASK 5 -- submission_readiness_report.md locked
section order + required epistemic labels. dataset-agnostic by
construction.
"""
from __future__ import annotations

from _etp_fixture import make_synthetic_run

from sift_sentinel.entity_truth_package import (
    SUBMISSION_READINESS_REPORT_GATE,
    SUBMISSION_READINESS_REPORT_MD,
    build_entity_truth_package,
)

_SECTIONS_IN_ORDER = [
    "## 1. Run Provenance",
    "## 2. Architecture Layers",
    "## 3. Confirmed Malicious Entities",
    "## 4. Contradicted Entities",
    "## 5. What This Run Proves",
    "## 6. What This Run Does NOT Prove",
    "## 7. Submission Compliance Checklist",
]

_REQUIRED_TEXT = [
    "TESTED: confirmed atomic findings compressed into fewer "
    "confirmed entities",
    "TESTED: contradicted entities routed out of confirmed malicious "
    "output",
    "VERIFIED: evidence integrity and DB5 gates from run summary when "
    "present",
    "INFERRED: malicious chain narratives do not promote contradicted "
    "members",
    "does not prove a premium model would find more",
    "does not resolve contradicted entities without a future tiebreaker",
    "KNOWN TEST DEBT: 3 validator tests assert case-insensitive "
    "filename/artifact matching; tracked as 31H-beta; not a pipeline "
    "regression for this diagnostic run when exact evidence strings "
    "matched.",
]


def _report(tmp_path) -> str:
    run_json = make_synthetic_run(tmp_path)
    out = tmp_path / "pkg"
    build_entity_truth_package(run_json, out)
    return (out / SUBMISSION_READINESS_REPORT_MD).read_text()


def test_sections_present_and_in_exact_order(tmp_path):
    md = _report(tmp_path)
    positions = [md.find(s) for s in _SECTIONS_IN_ORDER]
    assert all(p >= 0 for p in positions), positions
    assert positions == sorted(positions)


def test_required_epistemic_text_present(tmp_path):
    md = _report(tmp_path)
    for txt in _REQUIRED_TEXT:
        assert txt in md, txt


def test_compliance_checklist_items_present(tmp_path):
    md = _report(tmp_path)
    for item in (
        "dataset-agnostic package",
        "model-flexible",
        "model names redacted",
        "debug logs excluded",
        "host evidence paths redacted",
        "run_archive ignored by git",
    ):
        assert item in md, item


def test_readiness_report_gate_passes(tmp_path):
    run_json = make_synthetic_run(tmp_path)
    out = tmp_path / "pkg"
    result = build_entity_truth_package(run_json, out)
    assert result["gates"][SUBMISSION_READINESS_REPORT_GATE] == "PASS"
