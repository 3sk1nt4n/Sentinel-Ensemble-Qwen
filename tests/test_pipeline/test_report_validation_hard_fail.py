"""Slot 31E-DB.5.5 -- report validation can never end in PASS.

Dataset-agnostic. No API key, no live run, no network.
"""

from __future__ import annotations

from sift_sentinel.validation.report_gates import (
    enforce_report_validation_gate,
)
from sift_sentinel.validation.report_validation import validate_report


def test_report_validation_errors_hard_fail(capsys):
    # A finding missing tool_call_ids and raw_excerpt is a schema error.
    bad_finding = {"finding_id": "F-001", "artifact": "x"}
    report = {"report": "Narrative referencing F-001.",
              "findings": [bad_finding]}
    rv = validate_report(report, [bad_finding])
    assert rv["valid"] is False
    assert rv["errors"]

    summary = {"status": "completed"}
    rc = enforce_report_validation_gate(rv, summary)
    out = capsys.readouterr().out
    assert rc != 0
    assert "REPORT_VALIDATION_GATE=FAIL" in out
    assert "REPORT_VALIDATION_GATE=PASS" not in out
    assert summary["status"] == "completed_with_report_validation_issues"
    assert summary["gates"]["REPORT_VALIDATION_GATE"] == "FAIL"


def test_valid_report_emits_pass(capsys):
    good = {
        "finding_id": "F-001",
        "artifact": "payload.bin",
        "tool_call_ids": ["tc-1"],
        "raw_excerpt": "line 1: payload.bin",
        "source_tools": ["vol_pstree"],
        "confidence_level": "HIGH",
    }
    report = {"report": "Narrative referencing F-001.",
              "findings": [good]}
    rv = validate_report(report, [good])
    assert rv["valid"] is True

    summary = {"status": "completed"}
    rc = enforce_report_validation_gate(rv, summary)
    out = capsys.readouterr().out
    assert rc == 0
    assert "REPORT_VALIDATION_GATE=PASS" in out
    assert summary["gates"]["REPORT_VALIDATION_GATE"] == "PASS"
    assert summary["status"] == "completed"


def test_no_pass_emitted_when_errors_exist(capsys):
    rv = {"valid": False, "errors": ["missing tool_call_ids"],
          "warnings": []}
    rc = enforce_report_validation_gate(rv, None)
    out = capsys.readouterr().out
    assert rc == 1
    assert "FAIL" in out
    assert "REPORT_VALIDATION_GATE=PASS" not in out
