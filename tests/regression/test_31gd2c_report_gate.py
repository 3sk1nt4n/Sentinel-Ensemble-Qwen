"""31G-D2c post-run confirmed-section coverage gate."""

import json

from sift_sentinel.validation.report_gates import (
    check_confirmed_section_render_coverage,
    postrun_report_checks,
)


def _buckets(ids):
    return {
        "confirmed_malicious_atomic": [
            {"finding_id": fid, "title": "synthetic finding"} for fid in ids
        ],
        "suspicious_needs_review": [],
        "benign_or_false_positive": [],
        "inconclusive_unresolved": [],
        "synthesis_narrative": [],
    }


def _truth(ids, *, audit_gate="PASS", audit_missing=0):
    return {
        "bucket_counts": {
            "confirmed_malicious_atomic": len(ids),
            "suspicious_needs_review": 0,
            "benign_or_false_positive": 0,
            "inconclusive_unresolved": 0,
            "synthesis_narrative": 0,
        },
        "behavior_groups": [],
        "confirmed_section_render": {
            "schema_version": "confirmed_section_render_v1",
            "gate": audit_gate,
            "expected_count": len(ids),
            "covered_count": len(ids) - audit_missing,
            "missing_count": audit_missing,
            "missing_finding_ids": ids[-audit_missing:] if audit_missing else [],
            "heading_count": 1,
        },
    }


def _write_json(path, name, obj):
    (path / name).write_text(json.dumps(obj), encoding="utf-8")


def test_confirmed_section_coverage_passes_when_ids_are_in_one_section():
    ids = ["F100", "F101", "F102"]
    report = (
        "# R\n\n"
        "### Confirmed Malicious Atomic Findings (3 total)\n"
        "- **F100**: a\n- **F101**: b\n- **F102**: c\n\n"
        "## Requiring Further Investigation\n- x\n"
    )

    assert check_confirmed_section_render_coverage(
        report, _buckets(ids), _truth(ids)
    ) == []


def test_confirmed_section_coverage_catches_missing_id():
    ids = ["F200", "F201", "F202"]
    report = (
        "# R\n\n"
        "### Confirmed Malicious Atomic Findings (3 total)\n"
        "- **F200**: a\n- **F201**: b\n\n"
        "## Requiring Further Investigation\n- x\n"
    )

    errors = check_confirmed_section_render_coverage(
        report, _buckets(ids), _truth(ids)
    )

    assert any("confirmed_section_missing_ids" in e for e in errors)
    assert any("F202" in e for e in errors)


def test_confirmed_section_coverage_catches_duplicate_headings():
    ids = ["F300", "F301"]
    report = (
        "# R\n\n"
        "### Confirmed Malicious Atomic Findings (2 total)\n"
        "- **F300**: a\n- **F301**: b\n\n"
        "### Confirmed Malicious Findings\n"
        "- duplicate\n\n"
        "## Requiring Further Investigation\n- x\n"
    )

    errors = check_confirmed_section_render_coverage(
        report, _buckets(ids), _truth(ids)
    )

    assert any(e == "confirmed_section_heading_count:2" for e in errors)


def test_confirmed_section_coverage_honors_d2b_audit_gate():
    ids = ["F400"]
    report = (
        "# R\n\n"
        "### Confirmed Malicious Atomic Findings (1 total)\n"
        "- **F400**: a\n"
    )

    errors = check_confirmed_section_render_coverage(
        report, _buckets(ids), _truth(ids, audit_gate="FAIL")
    )

    assert "confirmed_section_render_gate:FAIL" in errors


def test_postrun_report_checks_fails_when_final_report_drops_confirmed_id(tmp_path):
    ids = ["F500", "F501"]
    _write_json(tmp_path, "report_validation.json", {"valid": True, "errors": []})
    _write_json(tmp_path, "finding_disposition_buckets.json", _buckets(ids))
    _write_json(tmp_path, "report_truth.json", _truth(ids))

    (tmp_path / "report.md").write_text(
        "# R\n\n"
        "### Confirmed Malicious Atomic Findings (2 total)\n"
        "- **F500**: a\n\n"
        "## Requiring Further Investigation\n- x\n",
        encoding="utf-8",
    )

    ok, errors = postrun_report_checks(str(tmp_path))

    assert ok is False
    assert any("confirmed_section_missing_ids" in e for e in errors)
    assert any("F501" in e for e in errors)


def test_postrun_report_checks_passes_when_final_report_covers_confirmed_ids(tmp_path):
    ids = ["F600", "F601"]
    _write_json(tmp_path, "report_validation.json", {"valid": True, "errors": []})
    _write_json(tmp_path, "finding_disposition_buckets.json", _buckets(ids))
    _write_json(tmp_path, "report_truth.json", _truth(ids))

    (tmp_path / "report.md").write_text(
        "# R\n\n"
        "### Confirmed Malicious Atomic Findings (2 total)\n"
        "- **F600**: a\n"
        "- **F601**: b\n\n"
        "## Requiring Further Investigation\n- x\n",
        encoding="utf-8",
    )

    ok, errors = postrun_report_checks(str(tmp_path))

    assert ok is True
    assert errors == []
