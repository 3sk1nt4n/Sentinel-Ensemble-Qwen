"""31G-D2b: confirmed-section replacer is wired before report validation.

This is a structural test. It does not run the pipeline or call APIs.
"""

from pathlib import Path


SRC = Path("run_pipeline.py").read_text()


def test_d2b_wire_exists_before_report_validation_payload() -> None:
    marker = "31G-D2b: deterministic confirmed-section replacement"
    assert marker in SRC

    marker_i = SRC.index(marker)
    payload_i = SRC.index('report_payload = {"report": report, "findings": _confirmed_atomic}')
    validate_i = SRC.index("report_check = validate_report(report_payload, _all_dispositioned)")

    assert marker_i < payload_i < validate_i


def test_d2b_uses_frozen_behavior_groups_and_not_flat_findings_for_render() -> None:
    marker_i = SRC.index("31G-D2b: deterministic confirmed-section replacement")
    payload_i = SRC.index('report_payload = {"report": report, "findings": _confirmed_atomic}')
    block = SRC[marker_i:payload_i]

    assert '_report_truth.get("behavior_groups")' in block
    assert "replace_confirmed_findings_section" in block
    assert "confirmed_finding_ids" in block
    assert "findings_final" not in block


def test_d2b_records_machine_readable_report_truth_gate() -> None:
    marker_i = SRC.index("31G-D2b: deterministic confirmed-section replacement")
    payload_i = SRC.index('report_payload = {"report": report, "findings": _confirmed_atomic}')
    block = SRC[marker_i:payload_i]

    assert 'confirmed_section_render' in block
    assert 'CONFIRMED_SECTION_RENDER_GATE' in block
    assert '"heading_count"' in block
    assert '"missing_finding_ids"' in block
    assert 'write_state(STATE_DIR, "report_truth.json", _report_truth)' in block


def test_d2b_checks_ids_inside_confirmed_section_not_whole_report() -> None:
    marker_i = SRC.index("31G-D2b: deterministic confirmed-section replacement")
    payload_i = SRC.index('report_payload = {"report": report, "findings": _confirmed_atomic}')
    block = SRC[marker_i:payload_i]

    assert "_d2b_section_text" in block
    assert "if _fid not in _d2b_section_text" in block
    assert "_d2b_heading_re" in block
